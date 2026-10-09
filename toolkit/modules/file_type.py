from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from frontend.viewmodels.tools_vm import ToolsViewModel

import mimetypes
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path

from toolkit.core import ModuleSpec
from toolkit.task_context import TaskContext

SAMPLE_BYTES = 1024 * 1024
NATIVE_HELP = (
    "Install python-magic and a compatible x64 libmagic DLL with its dependencies on PATH. "
    "Set TOOLKIT_MAGIC_FILE to the matching magic.mgc database. See README native setup."
)


@dataclass(frozen=True)
class FileReport:
    mime: str
    description: str
    extension: str
    expected_mime: str
    extension_status: str
    sample_bytes: int


def _database() -> str | None:
    from backend.platform_utils import magic_database

    try:
        filename = magic_database()
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    return str(filename) if filename else None


def readiness() -> str:
    try:
        _database()
        import_module("magic")
    except (ImportError, OSError, RuntimeError) as exc:
        return "Setup needed: " + NATIVE_HELP + " (" + str(exc) + ")"
    return ""


def extension_status(extension: str, mime: str) -> tuple[str, str]:
    expected = mimetypes.guess_type("sample" + extension, strict=False)[0] if extension else None
    aliases = {
        "application/x-zip-compressed": "application/zip",
        "image/x-png": "image/png",
        "application/x-pdf": "application/pdf",
        "application/x-gzip": "application/gzip",
    }
    if not extension:
        return "No extension", ""
    if not expected:
        return "Unknown extension", ""
    return (
        "Matches" if aliases.get(expected, expected) == aliases.get(mime, mime) else "Mismatch"
    ), expected


def identify_file(filename: str | Path, task: TaskContext | None = None) -> FileReport:
    task = task or TaskContext()
    task.check()
    path = Path(filename)
    if not path.is_file():
        raise ValueError("Choose a readable regular file.")
    database = _database()
    try:
        with path.open("rb") as source:
            sample = source.read(SAMPLE_BYTES)
    except OSError as exc:
        raise ValueError("Cannot read the selected file: " + str(exc)) from exc
    task.check()
    try:
        import magic

        # Each worker creates its own handles. The module never shares a Magic instance.
        mime_handle = magic.Magic(mime=True, magic_file=database)
        description_handle = magic.Magic(magic_file=database)
        mime = mime_handle.from_buffer(sample)
        description = description_handle.from_buffer(sample)
    except Exception as exc:
        raise RuntimeError(
            "File identification unavailable. " + NATIVE_HELP + " (" + str(exc) + ")"
        ) from exc
    task.check()
    state, expected = extension_status(path.suffix.lower(), mime)
    return FileReport(mime, description, path.suffix, expected, state, len(sample))


def identify_bytes(content: bytes, filename: str, task: TaskContext) -> FileReport:
    """Identify upload bytes; filenames affect only the extension comparison."""
    task.check()
    from backend.platform_utils import magic_database

    sample = content[:SAMPLE_BYTES]
    database_path = magic_database()
    database = str(database_path) if database_path else None
    try:
        import magic

        mime_handle = magic.Magic(mime=True, magic_file=database)
        description_handle = magic.Magic(magic_file=database)
        mime = mime_handle.from_buffer(sample)
        description = description_handle.from_buffer(sample)
    except Exception as exc:
        raise RuntimeError("File identification unavailable. " + NATIVE_HELP) from exc
    task.check()
    extension = Path(filename.replace("\\", "/")).suffix
    state, expected = extension_status(extension.lower(), mime)
    return FileReport(mime, description, extension, expected, state, len(sample))


def create_panel(context: ToolsViewModel) -> QWidget:
    from frontend.views.tools import create_panel as factory

    return factory(MODULE.id, context)


MODULE = ModuleSpec("file-type", "File Type Identifier", 70, create_panel)
