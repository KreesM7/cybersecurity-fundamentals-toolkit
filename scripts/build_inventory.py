"""Collect build-specific dependency notices and exact upstream source references.

Run with the build interpreter AFTER PyInstaller, once per platform. This reports
installed distributions actually referenced by Analysis-00.toc, not a pip freeze
that would incorrectly identify test tools as shipped application dependencies.
"""

import argparse
import ast
import hashlib
import importlib.metadata as metadata
import json
import platform
import shutil
import ssl
import sys
import urllib.request
from pathlib import Path


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--bundle",
        type=Path,
        required=True,
        help="Final one-folder output; excludes libraries filtered after Analysis",
    )
    parser.add_argument("--download-sources", action="store_true")
    args = parser.parse_args()
    contents = ast.literal_eval(args.analysis.read_text(encoding="utf-8"))
    rows = [
        row
        for part in contents
        if isinstance(part, list)
        for row in part
        if isinstance(row, tuple)
        and len(row) == 3
        and isinstance(row[2], str)
        and row[2] in {"PYMODULE", "PYSOURCE", "BINARY", "EXTENSION", "DATA"}
    ]
    rows = [
        row
        for row in rows
        if row[2] in {"PYMODULE", "PYSOURCE"}
        or (args.bundle / "_internal" / row[0]).is_file()
        or (args.bundle / row[0]).is_file()
    ]
    paths = {str(Path(row[1]).absolute()).casefold() for row in rows}
    modules = {row[0] for row in rows}
    if any(s == "scapy" or s.startswith("scapy.") for s in modules):
        raise RuntimeError("Scapy must never be included in the desktop")
    args.output.mkdir(parents=True, exist_ok=True)
    entries = []
    for dist in metadata.distributions():
        files = list(dist.files or [])
        matched = [f for f in files if str(dist.locate_file(f).absolute()).casefold() in paths]
        name = dist.metadata["Name"]
        if not matched and name.lower() != "pyinstaller":
            continue
        target = args.output / "licenses" / (name + "-" + dist.version)
        target.mkdir(parents=True, exist_ok=True)
        notices = []
        for item in files:
            if any(
                word in item.name.lower() for word in ("license", "copying", "copyright", "notice")
            ):
                source = Path(dist.locate_file(item))
                if source.is_file():
                    relative = str(item).replace("\\", "/").replace("../", "parent/")
                    dest = target / relative
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, dest)
                    notices.append(str(dest.relative_to(args.output)).replace("\\", "/"))
        data = dist.read_text("METADATA") or ""
        (target / "METADATA.txt").write_text(data, encoding="utf-8")
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{name}/{dist.version}/json", timeout=30
        ) as response:
            upstream = json.load(response)
        sources = [
            {"url": item["url"], "sha256": item["digests"]["sha256"], "file": item["filename"]}
            for item in upstream["urls"]
            if item["packagetype"] == "sdist"
        ]
        if args.download_sources:
            for item in sources:
                destination = args.output / "sources" / item["file"]
                destination.parent.mkdir(exist_ok=True)
                if not destination.exists():
                    with urllib.request.urlopen(item["url"], timeout=90) as response:
                        with destination.open("wb") as output:
                            shutil.copyfileobj(response, output)
                if hashlib.sha256(destination.read_bytes()).hexdigest() != item["sha256"]:
                    raise RuntimeError(f"Source digest mismatch: {name}")
        entries.append(
            {
                "name": name,
                "version": dist.version,
                "license": dist.metadata.get("License-Expression")
                or dist.metadata.get("License", ""),
                "license_classifiers": [
                    c for c in dist.metadata.get_all("Classifier", []) if c.startswith("License ::")
                ],
                "notices": notices,
                "sources": sources,
                "role": "build bootloader" if name.lower() == "pyinstaller" else "bundled",
                "matched_files": len(matched),
            }
        )
    result = {
        "platform": platform.platform(),
        "python": sys.version,
        "openssl": ssl.OPENSSL_VERSION,
        "python_source": f"https://www.python.org/ftp/python/{platform.python_version()}/Python-{platform.python_version()}.tar.xz",
        "qt_source": "https://download.qt.io/archive/qt/6.11/6.11.2/single/qt-everywhere-src-6.11.2.tar.xz",
        "dependencies": sorted(entries, key=lambda d: d["name"].lower()),
        "external_not_bundled": ["Scapy worker", "Metasploit", "Nmap", "libmagic"],
        "native_binaries": sorted({row[0] for row in rows if row[2] in {"BINARY", "EXTENSION"}}),
    }
    (args.output / "inventory.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Recorded {len(entries)} distributions for {platform.system()}.")


if __name__ == "__main__":
    main()
