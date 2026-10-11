"""Build a deterministic, pure-Python worker wheel without downloading build tooling."""

import base64
import csv
import hashlib
import io
import tomllib
import zipfile
from pathlib import Path


def build(root: Path) -> Path:
    project = tomllib.loads((root / "pyproject.toml").read_text("utf-8"))["project"]
    name, version = project["name"].replace("-", "_"), project["version"]
    metadata = f"{name}-{version}.dist-info"
    files = {
        path.relative_to(root / "src")
        .as_posix(): path.read_text("utf-8")
        .replace("\r\n", "\n")
        .encode()
        for path in sorted((root / "src" / name).rglob("*.py"))
    }
    fields = [
        "Metadata-Version: 2.4",
        f"Name: {project['name']}",
        f"Version: {version}",
        f"Summary: {project['description']}",
        f"Requires-Python: {project['requires-python']}",
        "License-Expression: MIT",
        "License-File: LICENSE",
        "License-File: THIRD_PARTY_NOTICES.md",
        *[f"Requires-Dist: {dependency}" for dependency in project["dependencies"]],
        "",
        "",
    ]
    files[f"{metadata}/METADATA"] = "\n".join(fields).encode()
    files[f"{metadata}/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: toolkit-reproducible-wheel\n"
        b"Root-Is-Purelib: true\nTag: py3-none-any\n"
    )
    files[f"{metadata}/entry_points.txt"] = (
        "[console_scripts]\n"
        + "\n".join(f"{key} = {value}" for key, value in project["scripts"].items())
        + "\n"
    ).encode()
    for license_name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        files[f"{metadata}/licenses/{license_name}"] = (
            (root / license_name).read_text("utf-8").encode()
        )
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for path, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([path, "sha256=" + digest, len(data)])
    writer.writerow([f"{metadata}/RECORD", "", ""])
    files[f"{metadata}/RECORD"] = record.getvalue().encode()
    output = root / "dist" / f"{name}-{version}-py3-none-any.whl"
    output.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as wheel:
        for path, data in sorted(files.items()):
            entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            wheel.writestr(entry, data)
    return output


if __name__ == "__main__":
    artifact = build(Path(__file__).resolve().parents[1] / "worker")
    print(artifact)
    print(hashlib.sha256(artifact.read_bytes()).hexdigest())
