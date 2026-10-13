"""Passive, local-only SecDesk doctor without loading Qt or starting a backend."""

import argparse
import json

from backend.platform_utils import find_nmap_binary
from toolkit.secdesk.registry import doctor, load_registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecDesk local environment checks")
    parser.add_argument("command", choices=["doctor"])
    parser.parse_args(argv)
    try:
        tools = [doctor(tool).model_dump(mode="json") for tool in load_registry()]
        nmap = find_nmap_binary()
        print(
            json.dumps(
                {
                    "tools": tools,
                    "dependencies": [{"id": "nmap", "found": bool(nmap)}],
                    "note": (
                        "Passive discovery only; service, permission "
                        "and license checks remain unknown."
                    ),
                }
            )
        )
        return 0
    except (OSError, ValueError):
        print(json.dumps({"error": "Unable to inspect manifests or native prerequisites"}))
        return 2
