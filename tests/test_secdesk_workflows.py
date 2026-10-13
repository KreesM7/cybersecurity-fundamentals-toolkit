"""Controlled fixtures verify integration; they never impersonate vendor outputs."""

import asyncio
import json
import shutil
import sys
from uuid import uuid4

import httpx
import pytest
from pydantic import RootModel, SecretStr

from backend.main import create_app
from shared.secdesk import NativeHandle, NativeInput, NativeSnapshot
from toolkit.secdesk.findings import read_findings
from toolkit.secdesk.registry import Check, doctor, load_guides, load_registry


@pytest.mark.parametrize(
    "data,suffix",
    [
        (b"[]", ".json"),
        (b"{}", ".json"),
        (b"{", ".json"),
        (b'[{"title":"first","title":"last"}]', ".json"),
        (b"bad,headers\na,b", ".csv"),
        (b'title,severity,target,evidence\na,high,b,"unterminated', ".csv"),
        (b"title,severity,target,evidence\na,high,b", ".csv"),
        (b"{}", ".exe"),
    ],
)
def test_findings_reject_malformed_or_ambiguous_records(data, suffix):
    with pytest.raises(ValueError):
        read_findings(data, suffix)


def test_guides_cli_scope_and_findings_format(capsys):
    import jsonschema

    from toolkit.secdesk.cli import main
    from toolkit.secdesk.registry import Guide

    guides = load_guides()
    assert {guide.id for guide in guides} == {"burp", "companion"}
    for guide in guides:
        jsonschema.validate(guide.model_dump(mode="json"), Guide.model_json_schema())
    assert main(["doctor"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert len(result["tools"]) == 10
    assert result["dependencies"][0]["id"] == "nmap"
    row = read_findings(
        b"title,severity,target,evidence\nObservation,info,127.0.0.1,fixture", ".csv"
    )[0]
    assert row.title == "Observation"
    with pytest.raises(ValueError):
        read_findings(b"x" * (5 * 1024 * 1024 + 1), ".json")


async def test_native_api_consent_idempotency_secret_transport_and_workspace_scope(
    tmp_path, monkeypatch
):
    from backend.tls import ensure_tls
    from frontend.api_client import ApiClient

    original = shutil.which
    monkeypatch.setattr(
        "toolkit.secdesk.registry.shutil.which",
        lambda name: original(name) if name == "sh" else sys.executable,
    )
    app = create_app("b" * 64, "native-fixture", tmp_path)
    async with app.router.lifespan_context(app):
        workspace = app.state.workspaces.active_id
        body = {
            "workspace_id": str(workspace),
            "tool_id": "tcpdump",
            "mode": "terminal",
        }
        headers = {"Authorization": "Bearer " + "b" * 64, "X-Request-ID": str(uuid4())}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://localhost"
        ) as client:
            assert (await client.post("/api/v1/secdesk/launch", json=body)).status_code == 401
            for value in (1, "true"):
                assert (
                    await client.post(
                        "/api/v1/secdesk/launch", json=body | {"authorized": value}, headers=headers
                    )
                ).status_code == 422
            assert not app.state.secdesk.owned
            response = await client.post("/api/v1/secdesk/launch", json=body, headers=headers)
            assert response.status_code == 200
            launched = NativeSnapshot.model_validate(response.json(), strict=False)
            duplicate = await client.post("/api/v1/secdesk/launch", json=body, headers=headers)
            assert duplicate.json()["id"] == str(launched.id)
            assert len(app.state.secdesk.owned) == 1
            conflict = await client.post(
                "/api/v1/secdesk/launch", json=body | {"tool_id": "wireshark"}, headers=headers
            )
            assert conflict.status_code == 409
            assert (await client.get("/api/v1/connection/shutdown-check", headers=headers)).json()[
                "confirmation_required"
            ]
            hidden = await client.get(
                f"/api/v1/secdesk/session/{launched.id}?workspace_id={uuid4()}", headers=headers
            )
            assert hidden.status_code == 422

        material = ensure_tls(tmp_path / "tls-fixture")
        api = ApiClient(
            "https://127.0.0.1:9443",
            material.client_context(),
            "b" * 64,
            transport=httpx.ASGITransport(app),
        )
        try:
            await api.request(
                "POST",
                "/api/v1/secdesk/input",
                NativeSnapshot,
                NativeInput(
                    id=launched.id,
                    workspace_id=workspace,
                    text=SecretStr("echo password=fixture-secret\r"),
                ),
            )
            handle = NativeHandle(id=launched.id, workspace_id=workspace)
            for _ in range(50):
                screen = app.state.secdesk.snapshot(handle).screen
                if "[REDACTED]" in screen:
                    break
                await asyncio.sleep(0.1)
            assert "[REDACTED]" in screen and "fixture-secret" not in screen
            await api.request("POST", "/api/v1/secdesk/close", NativeSnapshot, handle)
            assert app.state.secdesk.snapshot(handle).status == "closed"
            audit = await app.state.secdesk.audit(workspace)
            assert audit and not any(row.authorized for row in audit)
            assert all("fixture-secret" not in str(row) for row in audit)
        finally:
            await api.close()


async def test_findings_upload_merge_redaction_isolation_and_console_ack(tmp_path):
    app = create_app("c" * 64, "findings-fixture", tmp_path)
    async with app.router.lifespan_context(app):
        workspace = app.state.workspaces.active_id
        options = {"workspace_id": str(workspace), "tool_id": "nikto"}
        records = [
            {
                "title": "Observed configuration",
                "severity": "info",
                "target": "127.0.0.1",
                "evidence": "password=fixture-secret",
            }
        ]
        headers = {"Authorization": "Bearer " + "c" * 64, "X-Request-ID": str(uuid4())}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://localhost"
        ) as client:
            uploaded = await client.post(
                "/api/v1/secdesk/findings/upload",
                headers=headers,
                data={"options": json.dumps(options)},
                files={"file": ("fixture.json", json.dumps(records).encode())},
            )
            assert uploaded.status_code == 200 and uploaded.json()["inserted"] == 1
            repeated = await client.post(
                "/api/v1/secdesk/findings/import",
                headers=headers | {"X-Request-ID": str(uuid4())},
                json=options | {"records": records},
            )
            assert repeated.json()["merged"] == 1
            response = await client.get(
                f"/api/v1/secdesk/findings?workspace_id={workspace}", headers=headers
            )
            assert len(response.json()) == 1 and "fixture-secret" not in response.text
            bad = await client.post(
                "/api/v1/secdesk/findings/upload",
                headers=headers | {"X-Request-ID": str(uuid4())},
                data={"options": json.dumps(options)},
                files={"file": ("bad.csv", b"wrong")},
            )
            assert bad.status_code == 422
            console = await client.post(
                "/api/v1/secdesk/console",
                headers=headers | {"X-Request-ID": str(uuid4())},
                json={
                    "workspace_id": str(workspace),
                    "tool_id": "nessus",
                    "mode": "gui",
                },
            )
            assert console.json()["status"] == "acknowledged"
            assert not app.state.secdesk.owned
            audit = await app.state.secdesk.audit(workspace)
            assert audit[0].event == "console-request"
            from shared.workspaces import WorkspaceCreate

            other = await app.state.workspaces.create(WorkspaceCreate(name="Separate case"))
            assert await app.state.secdesk_findings.listing(other.id) == []


def test_secdesk_guides_native_controls_keyboard_and_findings_gui(monkeypatch):
    from datetime import UTC, datetime

    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QKeyEvent

    from frontend.views.secdesk import SecDeskPanel
    from shared.secdesk import FindingImportResult, FindingView
    from tests.v2.test_module_ui import ViewModelFixture

    vm = ViewModelFixture()
    panel = SecDeskPanel(vm)
    tools = load_registry()
    checks = [doctor(tool) for tool in tools]
    panel.update_state("secdesk-doctor", RootModel[list[Check]](checks))
    panel.show_tool(next(tool for tool in tools if tool.id == "tcpdump"))
    controls = panel.native_controls
    assert controls.terminal_button.isEnabled()
    controls.launch("terminal")
    assert vm.calls[-1][1][2] == "/api/v1/secdesk/launch"
    snapshot = NativeSnapshot(
        id=uuid4(),
        workspace_id=vm.workspace_id,
        tool_id="tcpdump",
        mode="terminal",
        status="running",
        screen="fixture",
    )
    controls.update_state("secdesk-launch", snapshot)
    assert controls.current().id == snapshot.id
    controls.update_state("secdesk-sessions", RootModel[list[NativeSnapshot]]([]))
    assert controls.current().id == snapshot.id and controls.stop_button.isEnabled()
    controls.terminal.keyPressEvent(
        QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_A, Qt.KeyboardModifier.NoModifier, "a")
    )
    controls.queue_resize(30, 100)
    controls.flush()
    assert any(call[1][2] == "/api/v1/secdesk/input" for call in vm.calls if call[0] == "mutate")
    controls.poll()
    controls.stop()
    controls.error("secdesk-input", "Unknown outcome")
    assert controls.pending == "" and "no command was repeated" in controls.status.text()
    panel.show_guide(next(guide for guide in load_guides() if guide.detect_usb))
    assert panel.usb_button.isVisibleTo(panel.stack.currentWidget())
    panel.check_usb()
    from toolkit.secdesk.companion import SerialPort

    panel.update_state("secdesk-usb", RootModel[list[SerialPort]]([]))
    assert "No serial ports" in panel.document.toPlainText()
    panel.show_findings()
    row = FindingView(
        id=uuid4(),
        tool_id="tcpdump",
        title="Observation",
        severity="info",
        target="127.0.0.1",
        evidence="fixture",
        created_at=datetime.now(UTC),
    )
    panel.findings.update_state("secdesk-findings", RootModel[list[FindingView]]([row]))
    assert "Observation" in panel.findings.output.toPlainText()
    panel.findings.update_state(
        "secdesk-findings-import", FindingImportResult(inserted=1, merged=0)
    )
    panel.findings.error("secdesk-findings", "Rejected")
    controls.update_state("workspace", uuid4())
    assert not controls.current() and not hasattr(controls, "consent")
    panel.deleteLater()


def test_companion_default_never_opens_or_sends():
    from toolkit.secdesk.companion import CompanionTransport

    transport = CompanionTransport()
    with pytest.raises(ValueError, match="Firmware protocol"):
        transport.connect("COM9")
    with pytest.raises(ValueError, match="protocol-backed"):
        transport.exchange("replay", b"anything", authorized=True)
    transport.close()


def test_prerequisites_are_passive_and_tool_switch_clears_old_terminal(tmp_path, monkeypatch):
    from toolkit.secdesk.registry import prerequisites

    monkeypatch.setattr("backend.platform_utils.find_nmap_binary", lambda: None)
    monkeypatch.setattr("toolkit.secdesk.companion.ports", lambda: [])
    checks = prerequisites()
    assert len(checks) == 4
    assert checks[0].status == "not_installed"
    assert all(check.version == "unknown" for check in checks)
    from frontend.widgets.native_controls import NativeControls
    from tests.v2.test_module_ui import ViewModelFixture

    vm = ViewModelFixture()
    controls = NativeControls(vm)
    controls.set_tool(next(tool for tool in load_registry() if tool.id == "tcpdump"))
    assert controls.status.property("state") == "idle"
    assert not controls.terminal.isVisibleTo(controls)
    row = NativeSnapshot(
        id=uuid4(),
        workspace_id=vm.workspace_id,
        tool_id="tcpdump",
        mode="terminal",
        status="running",
    )
    controls.update_state("secdesk-launch", row)
    assert controls.current() is not None
    controls.set_tool(next(tool for tool in load_registry() if tool.id == "aircrack-ng"))
    assert controls.current() is None and not controls.terminal.isEnabled()
    controls.deleteLater()
