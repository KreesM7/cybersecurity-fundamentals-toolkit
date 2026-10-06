from dataclasses import dataclass
import mimetypes
import os
from pathlib import Path

from toolkit.core import ModuleSpec
from toolkit.tasks import TaskContext

SAMPLE_BYTES = 1024 * 1024
NATIVE_HELP = ('Install python-magic and a compatible x64 libmagic DLL with its dependencies on PATH. '
               'Set TOOLKIT_MAGIC_FILE to the matching magic.mgc database. See README native setup.')


@dataclass(frozen=True)
class FileReport:
    mime: str
    description: str
    extension: str
    expected_mime: str
    extension_status: str
    sample_bytes: int


def _database():
    filename = os.environ.get('TOOLKIT_MAGIC_FILE')
    if filename and not Path(filename).is_file():
        raise RuntimeError('TOOLKIT_MAGIC_FILE does not point to a readable magic.mgc database.')
    return filename or None


def readiness():
    try:
        _database()
        import magic
    except (ImportError, OSError, RuntimeError) as exc:
        return 'Setup needed: ' + NATIVE_HELP + ' (' + str(exc) + ')'
    return ''


def extension_status(extension, mime):
    expected = mimetypes.guess_type('sample' + extension, strict=False)[0] if extension else None
    aliases = {'application/x-zip-compressed': 'application/zip', 'image/x-png': 'image/png',
               'application/x-pdf': 'application/pdf', 'application/x-gzip': 'application/gzip'}
    if not extension:
        return 'No extension', ''
    if not expected:
        return 'Unknown extension', ''
    return ('Matches' if aliases.get(expected, expected) == aliases.get(mime, mime) else 'Mismatch'), expected


def identify_file(filename, task=None):
    task = task or TaskContext()
    task.check()
    path = Path(filename)
    if not path.is_file():
        raise ValueError('Choose a readable regular file.')
    database = _database()
    try:
        with path.open('rb') as source:
            sample = source.read(SAMPLE_BYTES)
    except OSError as exc:
        raise ValueError('Cannot read the selected file: ' + str(exc)) from exc
    task.check()
    try:
        import magic
        # Each worker creates its own handles. The module never shares a Magic instance.
        mime_handle = magic.Magic(mime=True, magic_file=database)
        description_handle = magic.Magic(magic_file=database)
        mime = mime_handle.from_buffer(sample)
        description = description_handle.from_buffer(sample)
    except Exception as exc:
        raise RuntimeError('File identification unavailable. ' + NATIVE_HELP + ' (' + str(exc) + ')') from exc
    task.check()
    state, expected = extension_status(path.suffix.lower(), mime)
    return FileReport(mime, description, path.suffix, expected, state, len(sample))


def create_panel(context):
    from PySide6.QtWidgets import QPlainTextEdit
    from toolkit.widgets import FileInput, TaskPanel, technical_font

    panel = TaskPanel(context, 'File Type Identifier',
                      'Identify a file from its signature using libmagic. Reads at most the first 1 MiB. '
                      'A signature is evidence of a format, not evidence that a file is safe. '
                      'Extension comparisons are advisory and depend on known MIME mappings.')
    source = FileInput()
    panel.layout.addWidget(source)
    output = QPlainTextEdit()
    output.setReadOnly(True)
    output.setFont(technical_font())
    panel.layout.addWidget(output, 1)
    panel.add_footer()
    panel.status.setText(readiness() or 'Ready.')

    def run():
        filename = source.path.text()
        output.clear()

        def done(report):
            output.setPlainText(f'MIME type:       {report.mime}\n'
                                f'Signature:       {report.description}\n'
                                f'Extension:       {report.extension or "(none)"}\n'
                                f'Expected MIME:   {report.expected_mime or "unknown"}\n'
                                f'Extension check: {report.extension_status}\n'
                                f'Sample bytes:    {report.sample_bytes:,}')
            panel.status.setText('Done. Encrypted, polyglot, and unusual files may be ambiguous.')

        panel.start(lambda task: identify_file(filename, task), done)

    panel.run_button.clicked.connect(run)
    return panel


MODULE = ModuleSpec('file-type', 'File Type Identifier', 70, create_panel)
