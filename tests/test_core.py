import importlib
import tempfile
import unittest
from pathlib import Path


class DiscoveryTests(unittest.TestCase):
    def core(self):
        try:
            return importlib.import_module('toolkit.core')
        except ModuleNotFoundError:
            self.fail('The module discovery contract has not been implemented.')

    def test_bad_plugin_does_not_hide_valid_plugin(self):
        core = self.core()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'working.py').write_text(
                'from toolkit.core import ModuleSpec\n'
                'MODULE = ModuleSpec("working", "Working", 1, lambda context: None)\n'
            )
            (root / 'broken.py').write_text('raise RuntimeError("missing native component")\n')
            modules = core.discover_modules([root])
            self.assertEqual([m.spec.id for m in modules if m.spec], ['working'])
            self.assertTrue(any('missing native component' in m.error for m in modules))

    def test_duplicate_ids_are_reported(self):
        core = self.core()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('first', 'second'):
                (root / (name + '.py')).write_text(
                    'from toolkit.core import ModuleSpec\n'
                    'MODULE = ModuleSpec("same", "Same", 1, lambda context: None)\n'
                )
            modules = core.discover_modules([root])
            self.assertEqual(sum(m.spec is not None for m in modules), 1)
            self.assertTrue(any('Duplicate' in m.error for m in modules))


if __name__ == '__main__':
    unittest.main()
