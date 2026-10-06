import importlib
from pathlib import Path
import tempfile
import unittest


class FileTypeTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('toolkit.modules.file_type')
        except ModuleNotFoundError:
            self.fail('The file identifier has not been implemented.')

    def test_extension_mismatch_and_unknown_extension(self):
        module = self.module()
        self.assertEqual(module.extension_status('.txt', 'image/png')[0], 'Mismatch')
        self.assertEqual(module.extension_status('.png', 'image/png')[0], 'Matches')
        self.assertEqual(module.extension_status('.unfamiliar', 'image/png')[0], 'Unknown extension')

    def test_missing_file_and_database_are_actionable(self):
        module = self.module()
        with self.assertRaisesRegex(ValueError, 'file'):
            module.identify_file('this-file-does-not-exist.png')
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample.txt'
            path.write_text('hello')
            with patch.dict('os.environ', {'TOOLKIT_MAGIC_FILE': str(path.parent / 'absent.mgc')}):
                with self.assertRaisesRegex(RuntimeError, 'TOOLKIT_MAGIC_FILE'):
                    module.identify_file(path)

    def test_real_renamed_png_signature(self):
        module = self.module()
        if module.readiness():
            self.skipTest('External libmagic is absent. See README native setup.')
        import base64
        # A complete one-pixel PNG, deliberately named as text.
        png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a9bkAAAAASUVORK5CYII=')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'renamed.txt'
            path.write_bytes(png)
            report = module.identify_file(path)
            self.assertEqual(report.mime, 'image/png')
            self.assertIn('PNG', report.description)
            self.assertEqual(report.extension_status, 'Mismatch')
