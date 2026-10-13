# One-folder desktop. External Metasploit, Scapy, Nmap and libmagic are never bundled.
from pathlib import Path
import os
import sys
import hashlib
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
datas = (collect_data_files('toolkit.resources')
         + collect_data_files('toolkit.secdesk', includes=['registry.json', 'manifests/*.json'])
         + collect_data_files('frontend', includes=['resources/themes/*.qss', 'resources/icons/*', 'resources/examples/*'])
         + collect_data_files('backend.repositories.migrations', include_py_files=True)
         + collect_data_files('backend', includes=['resources/*.ps1'])
         + collect_data_files('zxcvbn') + [
    (str(root / 'examples'), 'examples'),
    (str(root / 'README.md'), '.'),
    (str(root / 'LICENSE'), '.'),
    (str(root / 'THIRD_PARTY_NOTICES.md'), '.'),
])
analysis = Analysis(
    [str(root / 'toolkit' / '__main__.py')],
    pathex=[str(root)],
    binaries=[],
    datas=datas,
    hiddenimports=(collect_submodules('toolkit.modules') + collect_submodules('backend.tools')
                   + collect_submodules('frontend.views')
                   + ['sqlalchemy.dialects.sqlite.aiosqlite',
                      'keyring.backends.Windows' if sys.platform == 'win32' else 'keyring.backends.SecretService',
                      'aiosqlite', 'magic', 'nmap', 'zxcvbn', 'psutil', 'bs4', 'urllib3']),
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'PySide6', 'shiboken6', 'scapy', 'toolkit_scapy_worker', 'pytest',
              '_pytest', 'mypy', 'librt', 'ast_serialize', 'PIL', 'pygments', 'weasyprint'],
    noarchive=False,
)
# Native libmagic is a separately managed prerequisite. Linux system libraries
# stay on the host (Ubuntu 24.04+); do not silently redistribute the host OS.
analysis.binaries = [entry for entry in analysis.binaries
                     if not Path(entry[0]).name.lower().startswith('libmagic')]
if sys.platform == 'win32':
    ffi = root / 'work/native/libffi-8.dll'
    if not ffi.is_file() or hashlib.sha256(ffi.read_bytes()).hexdigest() != 'eff52743773eb550fcc6ce3efc37c85724502233b6b002a35496d828bd7b280a':
        raise RuntimeError('Run scripts/prepare_windows_runtime.py before building Windows.')
    analysis.binaries = [(name, str(ffi) if Path(name).name.lower() == 'libffi-8.dll' else path, kind)
                         for name, path, kind in analysis.binaries]
if sys.platform.startswith('linux'):
    analysis.exclude_system_libraries()
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz, analysis.scripts, [],
    exclude_binaries=True,
    name='CybersecurityFundamentalsToolkit',
    icon=str(root / 'frontend/resources/icons/toolkit.ico') if sys.platform == 'win32' else None,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=bool(os.environ.get('TOOLKIT_BUILD_CONSOLE')),
    disable_windowed_traceback=False,
)
collection = COLLECT(exe, analysis.binaries, analysis.datas,
                     strip=False, upx=False, name='CybersecurityFundamentalsToolkit')
