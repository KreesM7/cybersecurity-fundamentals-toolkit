from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.platform_utils import atomic_private_write, protect_private_path, remove_private_tree


class PrivateStorageTests(unittest.TestCase):
    def test_deletion_is_limited_to_one_validated_private_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            root = profile / "workspaces"
            child = root / "1234"
            sibling = profile / "other"
            protect_private_path(child, directory=True)
            protect_private_path(root, directory=True)
            protect_private_path(sibling, directory=True)
            atomic_private_write(child / "data.db", b"fixture")
            atomic_private_write(sibling / "keep.txt", b"keep")
            for invalid in (root, sibling, child / "data.db"):
                with self.assertRaises(ValueError):
                    remove_private_tree(invalid, root)
            remove_private_tree(child, root)
            self.assertFalse(child.exists())
            self.assertEqual((sibling / "keep.txt").read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()


def test_windows_directory_children_inherit_private_acl(tmp_path: Path) -> None:
    import json
    import subprocess

    from backend.platform_utils import assert_private_path, is_windows, protect_private_path

    if not is_windows():
        return
    protect_private_path(tmp_path, directory=True)
    child = tmp_path / "sqlite-journal"
    child.write_bytes(b"temporary database transaction")
    # Elevated runners default new file ownership to Administrators, but the
    # inherited DACL must still grant access only to the current user.
    quoted = str(child).replace("'", "''")
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "$ErrorActionPreference='Stop'; "
            f"$acl = [System.IO.File]::GetAccessControl('{quoted}'); "
            "$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
            "@{sid=$sid; rules=@($acl.GetAccessRules($true,$true,"
            "[System.Security.Principal.SecurityIdentifier]) | ForEach-Object { "
            "@{sid=$_.IdentityReference.Value; inherited=$_.IsInherited; "
            "allow=($_.AccessControlType -eq 'Allow')} })} | ConvertTo-Json -Depth 4",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    acl = json.loads(result.stdout)
    assert acl["rules"], result.stderr
    assert all(
        rule == {"sid": acl["sid"], "inherited": True, "allow": True} for rule in acl["rules"]
    )
    protect_private_path(child)
    assert_private_path(child)
