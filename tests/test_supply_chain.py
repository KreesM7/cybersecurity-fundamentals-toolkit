import hashlib
import json
import shutil
from pathlib import Path

import pytest

from scripts.audit_dependencies import assess
from scripts.build_worker_wheel import build

ROOT = Path(__file__).resolve().parents[1]


def test_audit_blocks_fixes_and_reports_no_fix_exceptions():
    report = {
        "dependencies": [
            {
                "name": "fixture",
                "version": "1.0",
                "vulns": [
                    {"id": "CVE-fixture-fixed", "fix_versions": ["1.1"]},
                    {"id": "CVE-fixture-unfixed", "fix_versions": []},
                ],
            }
        ]
    }
    blocked, exceptions = assess(report)
    assert [row["id"] for row in blocked] == ["CVE-fixture-fixed"]
    assert [row["id"] for row in exceptions] == ["CVE-fixture-unfixed"]
    report["dependencies"][0]["vulns"][1]["fix_versions"] = ["1.2"]
    assert len(assess(report)[0]) == 2


@pytest.mark.parametrize(
    "report",
    [
        {"dependencies": []},
        {"dependencies": [{"name": "unresolved", "skip_reason": "not found"}]},
    ],
)
def test_incomplete_audit_fails_closed(report):
    with pytest.raises(ValueError):
        assess(report)


def test_worker_wheel_is_reproducible_and_matches_committed_hash(tmp_path):
    copied = tmp_path / "worker"
    shutil.copytree(
        ROOT / "worker",
        copied,
        ignore=shutil.ignore_patterns("dist", "build", "*.egg-info", "__pycache__"),
    )
    wheel = build(copied)
    first = wheel.read_bytes()
    assert build(copied).read_bytes() == first
    expected = (ROOT / "worker/requirements-provision.txt").read_text()
    assert "--hash=sha256:" + hashlib.sha256(first).hexdigest() in expected
    module = copied / "src/toolkit_scapy_worker/__init__.py"
    module.write_text(module.read_text() + "\n# changed fixture\n")
    assert hashlib.sha256(build(copied).read_bytes()).hexdigest() not in expected


def test_release_manifest_rejects_tampering_and_path_traversal(tmp_path):
    pytest.importorskip("cyclonedx")
    from scripts.release_supply_chain import verified_assets

    artifact = tmp_path / "fixture.zip"
    artifact.write_bytes(b"public fixture")
    manifest = tmp_path / "SHA256SUMS"
    record = hashlib.sha256(artifact.read_bytes()).hexdigest() + "  fixture.zip\n"
    manifest.write_text(record)
    assert verified_assets(tmp_path) == ["fixture.zip"]
    bundle = tmp_path / "fixture.zip.sigstore.json"
    bundle.write_text("{}")
    assert verified_assets(tmp_path) == ["fixture.zip"]
    extra = tmp_path / "unlisted.zip"
    extra.write_bytes(b"unlisted")
    with pytest.raises(ValueError, match="missing from checksum manifest"):
        verified_assets(tmp_path)
    extra.unlink()
    artifact.write_bytes(b"tampered")
    with pytest.raises(ValueError):
        verified_assets(tmp_path)
    manifest.write_text(record.replace("fixture.zip", "../fixture.zip"))
    with pytest.raises(ValueError):
        verified_assets(tmp_path)


def test_sbom_matches_authoritative_inventory(tmp_path):
    pytest.importorskip("cyclonedx")
    from scripts.release_supply_chain import make_sbom

    generated = make_sbom(ROOT, tmp_path, "windows", "v2.0.0", "a" * 40)
    bom = json.loads((tmp_path / generated[0]).read_text())
    original = ROOT / "docs/software-inventory/windows.json"
    inventory = json.loads(original.read_text())
    versions = {(c["name"].lower().replace("_", "-"), c.get("version")) for c in bom["components"]}
    assert all(
        (d["name"].lower().replace("_", "-"), d["version"]) in versions
        for d in inventory["dependencies"]
    )
    assert (tmp_path / generated[1]).read_bytes() == original.read_bytes()
    assert {
        "name": "toolkit:inventory-sha256",
        "value": hashlib.sha256(original.read_bytes()).hexdigest(),
    } in bom["metadata"]["properties"]


def test_dependabot_update_groups_and_action_pins():
    yaml = pytest.importorskip("yaml")
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    assert config["version"] == 2
    assert {row["package-ecosystem"] for row in config["updates"]} == {"pip", "github-actions"}
    for row in config["updates"]:
        assert row["schedule"]["interval"] == "weekly"
        assert row["groups"]["minor-and-patch"]["update-types"] == ["minor", "patch"]
    import re

    for path in (ROOT / ".github/workflows").glob("*.yml"):
        workflow = yaml.safe_load(path.read_text())
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    assert re.fullmatch(r"[^@]+@[a-f0-9]{40}", step["uses"])
