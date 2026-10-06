import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class StartupTests(unittest.TestCase):
    def test_module_self_test_exits_from_other_directory(self):
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ, PYTHONPATH=str(root), QT_QPA_PLATFORM='offscreen')
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, '-m', 'toolkit', '--self-test'],
                                    cwd=folder, env=environment, capture_output=True,
                                    timeout=20, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
