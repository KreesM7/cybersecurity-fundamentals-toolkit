"""Bind CycloneDX SBOMs to the tagged inventories and verified release artifacts."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verified_assets(directory: Path) -> list[str]:
    names = []
    for line in (directory / "SHA256SUMS").read_text("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match is None:
            raise ValueError("Invalid release checksum record")
        expected, name = match.groups()
        path = directory / name
        if name in names or name == "SHA256SUMS" or path.is_symlink() or digest(path) != expected:
            raise ValueError(f"Release checksum mismatch or duplicate: {name}")
        names.append(name)
    if not names:
        raise ValueError("Release has no checksummed artifacts")
    allowed = set(names) | {"SHA256SUMS"}
    allowed |= {name + ".sigstore.json" for name in allowed}
    unexpected = {path.name for path in directory.iterdir()} - allowed
    if unexpected:
        raise ValueError(f"Release assets missing from checksum manifest: {sorted(unexpected)}")
    return names


def make_sbom(source: Path, assets: Path, platform: str, tag: str, commit: str) -> list[str]:
    inventory_path = source / "docs" / "software-inventory" / f"{platform}.json"
    inventory = json.loads(inventory_path.read_text("utf-8"))
    dependencies = inventory["dependencies"]
    requirements = assets / f".{platform}-requirements.txt"
    requirements.write_text(
        "\n".join(f"{item['name']}=={item['version']}" for item in dependencies) + "\n", "utf-8"
    )
    name = f"Toolkit-{tag}-{platform}.cdx.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "requirements",
            str(requirements),
            "--pyproject",
            str(source / "pyproject.toml"),
            "--output-reproducible",
            "--sv",
            "1.6",
            "-o",
            str(assets / name),
        ],
        check=True,
    )
    bom = json.loads((assets / name).read_text("utf-8"))
    bom["metadata"]["properties"] = [
        {"name": "toolkit:release-tag", "value": tag},
        {"name": "toolkit:source-commit", "value": commit},
        {"name": "toolkit:inventory-sha256", "value": digest(inventory_path)},
        {"name": "toolkit:platform", "value": inventory["platform"]},
        {
            "name": "toolkit:scope",
            "value": "Frozen distribution inventory, not the build environment",
        },
    ]
    by_name = {re.sub(r"[-_.]+", "-", item["name"]).lower(): item for item in dependencies}
    for component in bom["components"]:
        item = by_name[re.sub(r"[-_.]+", "-", component["name"]).lower()]
        if item.get("license"):
            component["licenses"] = [{"license": {"name": item["license"]}}]
        component.setdefault("externalReferences", []).extend(
            {
                "type": "distribution",
                "url": entry["url"],
                "hashes": [{"alg": "SHA-256", "content": entry["sha256"]}],
            }
            for entry in item["sources"]
        )
    for filename in inventory["native_binaries"]:
        bom["components"].append(
            {"type": "file", "name": filename, "bom-ref": "native:" + filename}
        )
    bom["components"].append(
        {
            "type": "platform",
            "name": "CPython",
            "version": inventory["python"].split()[0],
            "externalReferences": [{"type": "distribution", "url": inventory["python_source"]}],
        }
    )
    text = json.dumps(bom, indent=2) + "\n"
    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(text)
    if errors:
        raise ValueError(f"Invalid CycloneDX SBOM: {errors}")
    (assets / name).write_text(text, "utf-8")
    inventory_name = f"Toolkit-{tag}-{platform}-inventory.json"
    (assets / inventory_name).write_bytes(inventory_path.read_bytes())
    requirements.unlink()
    return [name, inventory_name]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]+)?", args.tag):
        raise ValueError("Invalid release tag")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise ValueError("Release source must be an exact commit")
    originals = verified_assets(args.assets)
    generated = []
    for platform in ("windows", "linux"):
        generated.extend(make_sbom(args.source, args.assets, platform, args.tag, args.commit))
    names = sorted(set(originals + generated))
    (args.assets / "SHA256SUMS").write_text(
        "".join(f"{digest(args.assets / name)}  {name}\n" for name in names), "utf-8"
    )
    signing = names + ["SHA256SUMS"]
    (args.assets / "signing-list.txt").write_text("\n".join(signing) + "\n", "utf-8")
    uploads = generated + ["SHA256SUMS"] + [name + ".sigstore.json" for name in signing]
    (args.assets / "upload-list.txt").write_text("\n".join(uploads) + "\n", "utf-8")


if __name__ == "__main__":
    main()
