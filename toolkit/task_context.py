"""Cooperative pure task context; analysis never imports a Qt runtime."""

from collections.abc import Callable
from threading import Event


class CancelledError(Exception):
    pass


Cancelled = CancelledError


class TaskContext:
    def __init__(self, event: Event | None = None, report: Callable[[str], None] | None = None):
        self.event = event or Event()
        self.report = report or (lambda message: None)

    def check(self) -> None:
        if self.event.is_set():
            raise Cancelled("Cancelled.")

    def wait(self, seconds: float) -> None:
        if self.event.wait(max(0, seconds)):
            self.check()
