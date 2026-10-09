import time
from uuid import uuid4

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication, QCheckBox, QComboBox, QLineEdit

from frontend.views.modules import ModuleBrowser
from shared.modules import ModuleDetail, ModuleSearch, ModuleSummary, OptionSpec
from shared.workspaces import TargetTransfer


class ViewModelFixture(QObject):
    state_changed = pyqtSignal(str, object)
    action_error = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.workspace_id = uuid4()
        self.calls = []

    def __getattr__(self, name):
        return lambda *args: self.calls.append((name, args))


def test_browser_dynamic_fields_stale_payload_and_target_transfer():
    app = QApplication.instance() or QApplication([])
    vm = ViewModelFixture()
    panel = ModuleBrowser(vm)
    app.processEvents()
    path = "auxiliary/scanner/test"
    panel.update_state(
        "module-search",
        ModuleSearch(
            modules=[ModuleSummary(path=path, name="Fixture", kind="auxiliary", rank="normal")]
        ),
    )
    assert panel.tree.topLevelItem(0).childCount() == 1
    detail = ModuleDetail(
        path=path,
        framework_id=uuid4(),
        name="Fixture",
        description="<script>plain text</script>",
        options=[
            OptionSpec(name="RHOSTS", required=True),
            OptionSpec(name="SSL", kind="bool"),
            OptionSpec(name="MODE", choices=["one", "two"]),
            OptionSpec(name="PASSWORD", secret=True),
        ],
    )
    panel.update_state("module-detail", detail)
    assert isinstance(panel.fields["SSL"], QCheckBox)
    assert isinstance(panel.fields["MODE"], QComboBox)
    assert panel.fields["PASSWORD"].echoMode() == QLineEdit.EchoMode.Password
    transfer = TargetTransfer(target_id=uuid4(), workspace_id=vm.workspace_id, rhosts="127.0.0.1")
    panel.update_state("target-transfer", transfer)
    assert panel.fields["RHOSTS"].text() == "127.0.0.1"
    panel.owned.setChecked(True)
    panel.launch()
    request = vm.calls[-1][1][0]
    assert request.target_id == transfer.target_id and request.confirmed
    assert not panel.run.isEnabled()
    panel.update_state("workspace", uuid4())
    assert not panel.fields and panel.detail is None and not panel.owned.isChecked()
    panel.deleteLater()
    app.processEvents()


def test_app_navigation_real_tls_and_shutdown(tmp_path):
    from frontend.main_window import MainWindow
    from frontend.runtime import BackendThread
    from frontend.viewmodels.app_vm import AppViewModel

    app = QApplication.instance() or QApplication([])
    backend = BackendThread(tmp_path)
    ready, errors = [], []
    backend.ready.connect(lambda *args: ready.append(args))
    backend.failed.connect(errors.append)
    backend.start()
    vm = window = None
    try:
        deadline = time.monotonic() + 20
        while not ready and not errors and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        assert ready and not errors
        locator, tls, _ = ready[0]
        vm = AppViewModel(
            f"https://127.0.0.1:{locator.port}",
            tls.client_context(),
            locator.token.get_secret_value(),
        )
        window = MainWindow(vm)
        window.show()
        while vm.workspace_id is None and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        assert vm.workspace_id is not None
        for index in range(window.sidebar.count()):
            window.sidebar.setCurrentRow(index)
            app.processEvents()
        assert len(window.panels) == 7
        assert any(
            window.sidebar.item(i).text() == "Modules" for i in range(window.sidebar.count())
        )
        window.close()
        while vm.is_running and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        assert not vm.is_running and window._closing
    finally:
        if vm and vm.is_running:
            vm.close()
        backend.stop()
        assert backend.wait(15000)


def test_rpc_password_is_sent_only_at_explicit_transport_boundary():
    from shared.framework import RpcConnect

    request = RpcConnect(password="unique-fixture-secret", ca_pem="certificate")
    assert "unique-fixture-secret" not in repr(request)
    assert "unique-fixture-secret" not in request.model_dump_json()
    assert request.transport_dump()["password"] == "unique-fixture-secret"


def test_payload_controls_and_generation_request():
    from frontend.views.payloads import PayloadPanel
    from shared.payloads import PayloadCatalog

    app = QApplication.instance() or QApplication([])
    vm = ViewModelFixture()
    panel = PayloadPanel(vm)
    path = "payload/linux/x64/shell_reverse_tcp"
    panel.update_state(
        "generator-search",
        ModuleSearch(
            modules=[ModuleSummary(path=path, name="Fixture", kind="payload", rank="normal")]
        ),
    )
    panel.update_state(
        "generator-catalog", PayloadCatalog(formats=["raw", "python"], encoders=["generic/none"])
    )
    panel.update_state(
        "generator-detail",
        ModuleDetail(
            path=path, framework_id=uuid4(), name="Fixture", description="Fixture", options=[]
        ),
    )
    panel.owned.setChecked(True)
    panel.encoder.setCurrentIndex(1)
    panel.iterations.setValue(2)
    panel.start()
    request = vm.calls[-1][1][-1]
    assert request.encoder == "generic/none" and request.iterations == 2
    assert request.format == "raw" and request.confirmed and request.lhost == "127.0.0.1"
    assert not panel.generate.isEnabled() and not panel.save.isEnabled()
    panel.timer.stop()
    panel.deleteLater()
    app.processEvents()
