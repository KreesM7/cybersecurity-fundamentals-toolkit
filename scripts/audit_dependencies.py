"""Fail on fixable vulnerabilities or incomplete audits; report every no-fix exception."""

import argparse
import importlib.metadata
import json
import os
import subprocess
import sys
from pathlib import Path


def assess(report: dict) -> tuple[list[dict], list[dict]]:
    blocked, exceptions = [], []
    dependencies = report["dependencies"]
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("Audit report has no dependency results")
    for dependency in dependencies:
        if dependency.get("skip_reason"):
            # The editable project is our source, not a published dependency.
            if dependency["name"] != "cybersecurity-fundamentals-toolkit":
                raise ValueError(f"Incomplete dependency audit: {dependency['name']}")
            continue
        for finding in dependency["vulns"]:
            row = {
                "package": dependency["name"],
                "version": dependency["version"],
                "id": finding["id"],
                "aliases": finding.get("aliases", []),
                "fix_versions": finding["fix_versions"],
            }
            (blocked if row["fix_versions"] else exceptions).append(row)
    return blocked, exceptions


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/dependency-audit"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = args.output / "audit.json"
    report.unlink(missing_ok=True)
    requirements = args.output / "installed.txt"
    requirements.write_text(
        "\n".join(
            sorted(
                f"{item.metadata['Name']}=={item.version}"
                for item in importlib.metadata.distributions()
                if item.metadata["Name"] != "cybersecurity-fundamentals-toolkit"
            )
        )
        + "\n",
        "utf-8",
    )
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "--strict",
            "--no-deps",
            "--disable-pip",
            "-r",
            str(requirements),
            "-f",
            "json",
            "-o",
            str(report),
        ],
        check=False,
    )
    if process.returncode not in (0, 1) or not report.exists():
        raise SystemExit("Dependency audit failed before producing a complete report")
    blocked, exceptions = assess(json.loads(report.read_text("utf-8")))
    if process.returncode == 1 and not (blocked or exceptions):
        raise SystemExit("Audit failed without a vulnerability report")
    (args.output / "no-fix-exceptions.json").write_text(
        json.dumps(exceptions, indent=2) + "\n", "utf-8"
    )
    lines = [
        "# Dependency audit",
        "",
        f"Blocking findings: {len(blocked)}",
        f"No-fix exceptions: {len(exceptions)}",
        "",
    ]
    for item in exceptions:
        line = (
            f"{item['package']} {item['version']}: {item['id']} "
            "(no published fix; rechecked every run)"
        )
        lines.append("- " + line)
        print("::warning::" + line if os.environ.get("GITHUB_ACTIONS") else line)
    summary = "\n".join(lines) + "\n"
    (args.output / "exceptions.md").write_text(summary, "utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(summary)
    print(summary)
    raise SystemExit(bool(blocked))


if __name__ == "__main__":
    main()
