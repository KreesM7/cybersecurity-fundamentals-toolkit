"""Stage documentation/notices and source references in a completed frozen folder."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("compliance", type=Path)
    parser.add_argument("--native-notices", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if not args.bundle.is_dir() or not (args.compliance / "inventory.json").is_file():
        raise ValueError("Build the bundle and its inventory first")
    destination = args.bundle / "compliance"
    destination.mkdir(exist_ok=True)
    shutil.copyfile(args.compliance / "inventory.json", destination / "inventory.json")
    shutil.copytree(args.compliance / "licenses", destination / "licenses", dirs_exist_ok=True)
    shutil.copytree(args.native_notices, destination / "native", dirs_exist_ok=True)
    shutil.copytree(root / "docs", args.bundle / "docs", dirs_exist_ok=True)
    for name in ("LICENSE", "COPYING", "README.md", "THIRD_PARTY_NOTICES.md"):
        shutil.copyfile(root / name, args.bundle / name)
    # Hash actual native files after PyInstaller's post-analysis filters/replacements.
    binaries = {}
    for path in sorted((args.bundle / "_internal").rglob("*")):
        if path.is_file() and any(part in path.name for part in (".dll", ".pyd", ".so")):
            binaries[str(path.relative_to(args.bundle)).replace("\\", "/")] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    (destination / "binary-sha256.json").write_text(json.dumps(binaries, indent=2), "utf-8")
    print(f"Staged notices and hashes for {len(binaries)} native files.")


if __name__ == "__main__":
    main()
