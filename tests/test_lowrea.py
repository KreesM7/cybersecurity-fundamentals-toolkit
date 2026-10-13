import json

import pytest

from toolkit.lowrea.domain import Evidence


def test_evidence_is_stable_and_independent_of_input_mutation():
    facts = {"offset": 4, "names": ["main"]}
    first = Evidence.create("inspect_artifact", facts, subject_sha256="a" * 64)
    second = Evidence.create(
        "inspect_artifact", {"names": ["main"], "offset": 4}, subject_sha256="a" * 64
    )
    assert first.evidence_id == second.evidence_id
    facts["names"].append("changed")
    exported = first.record()
    exported["normalized_result"]["names"].append("changed")
    assert first.record()["normalized_result"]["names"] == ["main"]
    assert Evidence.from_record(json.loads(json.dumps(first.record()))) == first


def test_evidence_rejects_tampering_and_nonfinite_numbers():
    evidence = Evidence.create("inspect_artifact", {"size": 4})
    record = evidence.record()
    record["normalized_result"]["size"] = 5
    with pytest.raises(ValueError, match="digest"):
        Evidence.from_record(record)
    with pytest.raises(ValueError):
        Evidence.create("inspect_artifact", {"value": float("nan")})


@pytest.mark.parametrize("kind", ["file", "missing", "directory"])
def test_real_cli_records_identity_without_running_target(tmp_path, kind, capsys):
    import hashlib
    import subprocess
    import sys

    path = tmp_path / "target.py"
    if kind == "file":
        path.write_text("raise SystemExit(77)", encoding="utf8")
    elif kind == "directory":
        path.mkdir()
    result = subprocess.run(
        [sys.executable, "-m", "toolkit", "lowrea", "inventory-artifact", str(path)],
        capture_output=True,
        timeout=10,
    )
    record = json.loads(result.stdout)
    assert result.returncode == (0 if kind == "file" else 1)
    assert record["isError"] is (kind != "file")
    if kind == "file":
        assert record["evidence"]["subject_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert Evidence.from_record(record["evidence"]).record() == record["evidence"]
    else:
        assert record["error"]["remediation"]
    from toolkit.lowrea.cli import main

    assert main(["inventory-artifact", str(path)]) == result.returncode
    assert json.loads(capsys.readouterr().out) == record


def test_invalid_evidence_identity_and_schema():
    with pytest.raises(ValueError):
        Evidence.create("", {})
    with pytest.raises(ValueError):
        Evidence.create("inspect_artifact", {}, subject_sha256="invalid")
    evidence = Evidence.create("inspect_artifact", {})
    record = evidence.record()
    record["schema_version"] = 2
    import hashlib

    payload = dict(record)
    payload.pop("evidence_id")
    record["evidence_id"] = (
        "ev:" + hashlib.sha256(Evidence._serialize(payload).encode("utf8")).hexdigest()
    )
    with pytest.raises(ValueError, match="schema"):
        Evidence.from_record(record)


def test_changed_artifact_reports_failure(tmp_path, monkeypatch, capsys):
    from toolkit.lowrea.cli import main

    path = tmp_path / "artifact"
    path.write_bytes(b"before")
    from toolkit.lowrea import cli

    original = cli.read_identity

    def change_during_digest(stream, expected_size):
        digest = original(stream, expected_size)
        path.write_bytes(b"after-change")
        return digest

    monkeypatch.setattr(cli, "read_identity", change_during_digest)
    assert main(["inventory-artifact", str(path)]) == 1
    assert "changed" in json.loads(capsys.readouterr().out)["error"]["reason"]


@pytest.mark.parametrize(
    "field,value", [("operation", ""), ("subject_sha256", "invalid"), ("confidence", "certain")]
)
def test_payload_validation_cannot_be_bypassed_with_valid_digest(field, value):
    record = Evidence.create("inspect_artifact", {}).record()
    record.pop("evidence_id")
    record[field] = value
    with pytest.raises(ValueError):
        Evidence(canonical_json=json.dumps(record))


def test_direct_construction_canonicalizes_and_rejects_duplicate_fields():
    record = Evidence.create("inspect_artifact", {}).record()
    record.pop("evidence_id")
    forward = Evidence(canonical_json=json.dumps(record))
    reverse = Evidence(canonical_json=json.dumps(dict(reversed(list(record.items())))))
    assert forward.evidence_id == reverse.evidence_id
    with pytest.raises(ValueError, match="Duplicate"):
        Evidence(canonical_json='{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError):
        Evidence(canonical_json="{}")


def test_failed_stream_creation_closes_owned_descriptor(tmp_path, monkeypatch, capsys):
    import os

    from toolkit.lowrea import cli

    path = tmp_path / "artifact"
    path.write_bytes(b"owned")
    opened = []
    original = os.open

    def capture_descriptor(*args, **kwargs):
        descriptor = original(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def fail_stream(*args, **kwargs):
        raise OSError("Cannot create stream")

    monkeypatch.setattr(cli.os, "open", capture_descriptor)
    monkeypatch.setattr(cli.os, "fdopen", fail_stream)
    assert cli.main(["inventory-artifact", str(path)]) == 1
    assert json.loads(capsys.readouterr().out)["isError"]
    with pytest.raises(OSError):
        os.fstat(opened[0])
