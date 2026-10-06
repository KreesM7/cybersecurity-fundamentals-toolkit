# Local build only. See THIRD_PARTY_NOTICES.md before considering redistribution.
from pathlib import Path
import os
import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

root = Path(SPECPATH)
sys.path.insert(0, str(root))
if sys.platform == 'win32':
    # Qt uses Windows' ICU. A foreign icuuc.dll on PATH can be collected instead
    # and break QtCore at startup. Restrict native discovery to this Python/OS.
    windows = Path(os.environ.get('SystemRoot', 'C:/Windows'))
    os.environ['PATH'] = os.pathsep.join([
        str(Path(sys.base_prefix)), str(Path(sys.prefix) / 'Scripts'),
        str(windows / 'System32'), str(windows),
    ])
datas = collect_data_files('toolkit.resources') + [
    (str(root / 'examples'), 'examples'),
    (str(root / 'README.md'), '.'),
    (str(root / 'LICENSE'), '.'),
    (str(root / 'THIRD_PARTY_NOTICES.md'), '.'),
]
analysis = Analysis(
    [str(root / 'toolkit' / '__main__.py')],
    pathex=[str(root)],
    binaries=[],
    datas=datas,
    hiddenimports=collect_submodules('toolkit.modules'),
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'PySide6.QtWebEngineWidgets'],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz, analysis.scripts, [],
    exclude_binaries=True,
    name='CybersecurityFundamentalsToolkit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)
collection = COLLECT(exe, analysis.binaries, analysis.datas,
                     strip=False, upx=False, name='CybersecurityFundamentalsToolkit')
