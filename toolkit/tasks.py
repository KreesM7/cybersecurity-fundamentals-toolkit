from threading import Event

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal


class Cancelled(Exception):
    pass


class TaskContext:
    def __init__(self, event=None, report=None):
        self.event = event or Event()
        self.report = report or (lambda message: None)

    def check(self):
        if self.event.is_set():
            raise Cancelled('Cancelled.')

    def wait(self, seconds):
        if self.event.wait(max(0, seconds)):
            self.check()


class TaskHandle(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    progress = Signal(str)
    finished = Signal()

    def __init__(self, parent):
        super().__init__(parent)
        self.cancel_event = Event()

    def cancel(self):
        self.cancel_event.set()


class Worker(QRunnable):
    def __init__(self, handle, work):
        super().__init__()
        self.handle, self.work = handle, work

    def run(self):
        task = TaskContext(self.handle.cancel_event, self.handle.progress.emit)
        try:
            task.check()
            result = self.work(task)
            task.check()
            self.handle.succeeded.emit(result)
        except Cancelled:
            self.handle.failed.emit('Cancelled. Partial results were discarded.')
        except Exception as exc:
            self.handle.failed.emit(str(exc) or type(exc).__name__)
        finally:
            self.handle.finished.emit()


class AppContext(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(2)
        self.jobs = set()

    def run_task(self, work, on_result, on_error, on_progress=None, on_finished=None):
        handle = TaskHandle(self)
        self.jobs.add(handle)
        handle.succeeded.connect(on_result)
        handle.failed.connect(on_error)
        if on_progress:
            handle.progress.connect(on_progress)
        if on_finished:
            handle.finished.connect(on_finished)
        handle.finished.connect(lambda: self._forget(handle))
        self.pool.start(Worker(handle, work))
        return handle

    def _forget(self, handle):
        self.jobs.discard(handle)
        handle.deleteLater()

    def cancel_all(self):
        for handle in tuple(self.jobs):
            handle.cancel()

    @staticmethod
    def resource_text(name):
        from toolkit.core import resource_text
        return resource_text(name)
