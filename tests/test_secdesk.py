import pytest

from toolkit.secdesk.registry import Check, ToolManifest, doctor, load_registry


def test_registry_and_json_schema():
    import jsonschema

    tools = load_registry()
    assert len(tools) == 10
    assert {"wireshark", "tcpdump", "metasploit", "forcepoint"} <= {tool.id for tool in tools}
    for tool in tools:
        jsonschema.validate(tool.model_dump(mode="json"), ToolManifest.model_json_schema())
    with pytest.raises(ValueError):
        ToolManifest.model_validate({"id": "nmap"})


def test_doctor_never_executes_or_guesses_permissions(tmp_path, monkeypatch):
    tool = load_registry()[0]
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.setattr("toolkit.secdesk.registry.shutil.which", lambda name: None)
    assert doctor(tool).status == "not_installed"
    binary = tmp_path / "tool.exe"
    binary.write_bytes(b"fixture, never executed")
    monkeypatch.setattr("toolkit.secdesk.registry.shutil.which", lambda name: str(binary))
    result = doctor(tool)
    assert result.status == "needs_setup"
    assert result.version == "unknown"
    assert "unverified" in result.reason
    assert binary.read_bytes() == b"fixture, never executed"


def test_manifest_rejects_untrusted_links_and_extra_fields():
    payload = load_registry()[0].model_dump(mode="json")
    payload["docs_link"] = "javascript:alert(1)"
    with pytest.raises(ValueError):
        ToolManifest.model_validate(payload)
    payload["docs_link"] = "https://www.wireshark.org/docs/"
    payload["shell"] = "anything"
    with pytest.raises(ValueError):
        ToolManifest.model_validate(payload)


async def test_authenticated_passive_doctor_endpoint(tmp_path, monkeypatch):
    import httpx

    from backend.main import create_app

    monkeypatch.setattr("toolkit.secdesk.registry.shutil.which", lambda name: None)
    app = create_app("a" * 64, "secdesk", tmp_path)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://localhost"
        ) as client:
            assert (await client.get("/api/v1/secdesk/doctor")).status_code == 401
            response = await client.get(
                "/api/v1/secdesk/doctor", headers={"Authorization": "Bearer " + "a" * 64}
            )
            assert response.status_code == 200
            assert len(response.json()) == 10
            assert all(row["version"] == "unknown" for row in response.json())


def test_registry_is_independent_of_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert len(load_registry()) == 10


def test_gui_details_missing_badges_and_manifest_failure(monkeypatch):
    from pydantic import RootModel

    from frontend.views.secdesk import SecDeskPanel
    from tests.v2.test_module_ui import ViewModelFixture

    panel = SecDeskPanel(ViewModelFixture())
    checks = [doctor(tool) for tool in panel.tools]
    panel.update_state("secdesk-doctor", RootModel[list[Check]](checks))
    for badge in panel.badges.values():
        assert badge.property("state") == "failed"
        assert "Ready" not in badge.text()
    panel.show_tool(panel.tools[0])
    assert panel.stack.currentIndex() == 1
    assert "1. Overview" in panel.document.toPlainText()
    assert "7. Launch" in panel.document.toPlainText()
    assert "Unverified" in panel.document.toPlainText()
    panel.deleteLater()

    def malformed():
        raise ValueError("Corrupt manifest")

    monkeypatch.setattr("frontend.views.secdesk.load_registry", malformed)
    broken = SecDeskPanel(ViewModelFixture())
    assert broken.status.property("state") == "failed"
    assert not broken.tools
    broken.deleteLater()


def test_missing_required_manifests_fail_closed(tmp_path):
    with pytest.raises(ValueError, match="Required tool manifests missing"):
        load_registry(tmp_path)
    tool = load_registry()[0]
    (tmp_path / "one.json").write_text(tool.model_dump_json(), encoding="utf8")
    with pytest.raises(ValueError, match="Required tool manifests missing"):
        load_registry(tmp_path)


def test_detection_rejects_absolute_or_escaping_paths():
    from toolkit.secdesk.registry import Detection

    for path in ("C:/tools/tool.exe", "../tool.exe", r"\\server\tool.exe", "/tool.exe"):
        with pytest.raises(ValueError):
            Detection(binary="tool", version_flag="--version", windows_program_files_path=path)


def test_headless_tshark_discovery_does_not_require_gui(tmp_path, monkeypatch):
    from toolkit.secdesk.registry import locate_binary

    tool = next(tool for tool in load_registry() if tool.id == "wireshark")
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.setattr(
        "toolkit.secdesk.registry.shutil.which",
        lambda name: "/fixture/tshark" if name == "tshark" else None,
    )
    assert locate_binary(tool, terminal=True) == "/fixture/tshark"
    assert locate_binary(tool) is None
    assert doctor(tool).status == "needs_setup"
