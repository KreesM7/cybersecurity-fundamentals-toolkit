"""The sole adapter for platform decisions, private files and owned processes."""

import asyncio
import ctypes
import importlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from contextlib import suppress
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, TypedDict


def is_windows() -> bool:
    """Whether the active platform uses Windows APIs."""
    return sys.platform == "win32"


def is_linux() -> bool:
    """Whether Linux platform conventions apply."""
    return sys.platform.startswith("linux")


def get_config_dir() -> Path:
    """Return an isolated override or the native per-user application directory."""
    override = os.environ.get("TOOLKIT_PROFILE")
    if override:
        return Path(override).expanduser().absolute()
    if is_windows():
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        return Path.home() / ".cybersecurity-fundamentals-toolkit"
    return base / "CybersecurityFundamentalsToolkit"


def get_log_dir() -> Path:
    """Logs belong to the active isolated profile."""
    return get_config_dir() / "logs"


def executable(name: str) -> Path | None:
    """Discover a simple executable name without a shell."""
    if not name or Path(name).name != name or "/" in name or "\\" in name:
        raise ValueError("Expected a simple executable name")
    found = shutil.which(name)
    return Path(found) if found else None


def find_nmap_binary() -> Path | None:
    """Locate native Nmap; an invalid explicit override fails instead of falling back."""
    override = os.environ.get("TOOLKIT_NMAP")
    if override:
        candidate = Path(override).expanduser().absolute()
        if not candidate.is_file() or (not is_windows() and not os.access(candidate, os.X_OK)):
            raise ValueError("TOOLKIT_NMAP must name an existing executable Nmap file.")
        return candidate
    found = executable("nmap")
    if found is not None:
        return found
    if is_windows():
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            directory = os.environ.get(variable)
            if directory:
                candidate = Path(directory) / "Nmap" / "nmap.exe"
                if candidate.is_file():
                    return candidate
    return None


def magic_database() -> Path | None:
    """Validate an optional external libmagic database without creating native handles."""
    override = os.environ.get("TOOLKIT_MAGIC_FILE")
    if not override:
        return None
    candidate = Path(override).expanduser().absolute()
    if not candidate.is_file():
        raise ValueError("TOOLKIT_MAGIC_FILE must name an existing magic.mgc database.")
    return candidate


def find_msf_binary(name: str) -> Path | None:
    """Discover a native Metasploit entry point; WSL is a separate invocation."""
    if name not in {"msfconsole", "msfrpcd", "msfvenom"}:
        raise ValueError("Unsupported Metasploit executable")
    discovered = executable(name)
    if discovered:
        return discovered
    for directory in (
        Path("/opt/metasploit-framework/bin"),
        Path("/usr/share/metasploit-framework"),
    ):
        candidate = directory / name
        if not is_windows() and candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def wsl_argv(args: Sequence[str]) -> list[str]:
    """Use one fixed distro and exec argument boundaries, never shell syntax."""
    if not args or any("\0" in argument for argument in args):
        raise ValueError("Nonempty executable arguments are required")
    return ["wsl.exe", "--distribution", "Toolkit-MSF", "--exec", *args]


def framework_host_argv(token: str, *, cancel: bool = False) -> list[str]:
    """Invoke only the separately provisioned private framework host."""
    import re

    if not re.fullmatch(r"[a-f0-9]{32}", token):
        raise ValueError("Invalid framework control token")
    arguments = [
        "/opt/toolkit-msf/venv/bin/python",
        "/opt/toolkit-msf/pty-host.py",
        "--token",
        token,
    ]
    if cancel:
        arguments.append("--cancel")
    return wsl_argv(arguments) if is_windows() else arguments


def capture_worker_argv(arguments: Sequence[str]) -> list[str]:
    """Invoke only the independently installed worker, never frozen application Python."""
    if is_windows():
        return wsl_argv(["/opt/toolkit-scapy/bin/python", "-m", "toolkit_scapy_worker", *arguments])
    override = os.environ.get("TOOLKIT_SCAPY_PYTHON", "/opt/toolkit-scapy/bin/python")
    candidate = Path(override).expanduser()
    if not candidate.is_absolute() or not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise ValueError("Install the separate capture worker. See docs/SCAPY_WORKER.md.")
    return [str(candidate), "-m", "toolkit_scapy_worker", *arguments]


class HiddenProcessOptions(TypedDict):
    creationflags: int


def hidden_process_options() -> HiddenProcessOptions:
    """Do not open a console window for an owned helper."""
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


def _reject_links(path: Path) -> None:
    for component in (path, *path.absolute().parents):
        if component.is_symlink():
            raise ValueError("Unsafe symlink in private profile path")
        if component.exists():
            info = component.stat(follow_symlinks=False)
            if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ValueError("Unsafe symlink or reparse point in private profile path")


def _windows_sid() -> str:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    security.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    security.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = wintypes.HANDLE()
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(handle)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        length = wintypes.DWORD()
        security.GetTokenInformation(handle, 1, None, 0, ctypes.byref(length))
        buffer = ctypes.create_string_buffer(length.value)
        if not security.GetTokenInformation(handle, 1, buffer, length, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.c_void_p.from_buffer(buffer)
        return _sid_string(sid)
    finally:
        kernel.CloseHandle(handle)


def _sid_string(sid: ctypes.c_void_p) -> str:
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    result = wintypes.LPWSTR()
    if not security.ConvertSidToStringSidW(sid, ctypes.byref(result)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if result.value is None:
            raise PermissionError("Windows returned an empty SID")
        return result.value
    finally:
        kernel.LocalFree(ctypes.cast(result, ctypes.c_void_p))


def _protect_windows(path: Path) -> None:
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    security.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    flags = "OICI" if path.is_dir() else ""
    sddl = f"D:P(A;{flags};FA;;;{_windows_sid()})"
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not security.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


class _Acl(ctypes.Structure):
    _fields_ = [
        ("revision", wintypes.BYTE),
        ("reserved", wintypes.BYTE),
        ("size", wintypes.WORD),
        ("count", wintypes.WORD),
        ("reserved2", wintypes.WORD),
    ]


def _assert_windows_private(path: Path) -> None:
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.GetNamedSecurityInfoW.restype = wintypes.DWORD
    security.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    code = security.GetNamedSecurityInfoW(
        str(path),
        1,
        0x00000005,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if code:
        raise ctypes.WinError(code)
    try:
        sid = _windows_sid()
        if _sid_string(owner) != sid or not dacl.value:
            raise PermissionError("Private file must have a current-user owner and DACL")
        acl = _Acl.from_address(dacl.value)
        grants_rw = False
        for index in range(acl.count):
            ace = ctypes.c_void_p()
            if not security.GetAce(dacl, index, ctypes.byref(ace)) or ace.value is None:
                raise PermissionError("Could not verify private file ACL")
            ace_type = ctypes.c_ubyte.from_address(ace.value).value
            mask = ctypes.c_uint32.from_address(ace.value + 4).value
            # Only ordinary owner allow entries are permitted; object/callback ACEs fail closed.
            if ace_type != 0 or _sid_string(ctypes.c_void_p(ace.value + 8)) != sid:
                raise PermissionError("Private file ACL grants access outside the current user")
            grants_rw |= bool(mask & 0x10000000 or mask & 0x00000003 == 0x00000003)
        if not grants_rw:
            raise PermissionError("Private file ACL does not grant owner read/write access")
    finally:
        kernel.LocalFree(descriptor)


def assert_private_path(path: Path) -> None:
    """Reject links or ownership/permissions that expose private profile material."""
    _reject_links(path)
    if is_windows():
        _assert_windows_private(path)
    else:
        info = path.stat(follow_symlinks=False)
        expected = 0o700 if path.is_dir() else 0o600
        if info.st_uid != getattr(os, "getuid")() or stat.S_IMODE(info.st_mode) != expected:
            raise PermissionError(
                "Private path must be owned by the current user with owner-only mode"
            )


def protect_private_path(path: Path, directory: bool = False) -> None:
    """Apply checked owner-only protection; directories may be created safely."""
    _reject_links(path)
    if directory:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if is_windows():
        _protect_windows(path)
    else:
        path.chmod(0o700 if directory else 0o600)
    assert_private_path(path)


def atomic_private_write(path: Path, data: bytes) -> None:
    """Write through an owner-only temporary file and atomically replace the destination."""
    _reject_links(path)
    protect_private_path(path.parent, directory=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        protect_private_path(temporary)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _reject_links(path)
        os.replace(temporary, path)
        assert_private_path(path)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def remove_private_tree(path: Path, root: Path) -> None:
    """Delete exactly one private child of the intended root, never a link or reparse tree."""
    _reject_links(root)
    _reject_links(path)
    resolved_root = root.resolve(strict=True)
    resolved_target = path.resolve(strict=True)
    if resolved_target.parent != resolved_root or not resolved_target.is_dir():
        raise ValueError("Deletion target must be a direct directory child of the workspace root.")
    assert_private_path(resolved_root)
    pending = [resolved_target]
    while pending:
        current = pending.pop()
        _reject_links(current)
        assert_private_path(current)
        if current.is_dir():
            pending.extend(current.iterdir())
    # Recheck resolved containment immediately before the recursive operation.
    _reject_links(resolved_target)
    if resolved_target.resolve(strict=True).parent != resolved_root:
        raise ValueError("Deletion target changed during validation.")
    shutil.rmtree(resolved_target)


class ProfileInUseError(RuntimeError):
    """Another live backend holds the profile's advisory lock."""


ProfileInUse = ProfileInUseError


class ProfileLease:
    """Keep a platform advisory file lock alive until explicit shutdown."""

    def __init__(self, stream: BinaryIO) -> None:
        self._stream: BinaryIO | None = stream

    def close(self) -> None:
        """Release the lock without removing the guard file."""
        stream, self._stream = self._stream, None
        if stream is not None:
            stream.close()


def acquire_profile_lease(profile: Path) -> ProfileLease:
    """Acquire a nonblocking OS lock; stale PIDs never justify deleting a live lock."""
    protect_private_path(profile, directory=True)
    guard = profile / ".instance.lock"
    _reject_links(guard)
    existed = guard.exists()
    if existed:
        assert_private_path(guard)
    descriptor = os.open(guard, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    stream = os.fdopen(descriptor, "r+b")
    try:
        if not existed:
            protect_private_path(guard)
        if is_windows():
            import msvcrt

            if guard.stat().st_size == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            fcntl = importlib.import_module("fcntl")
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        stream.close()
        raise ProfileInUse("The toolkit profile is already in use") from exc
    except BaseException:
        stream.close()
        raise
    return ProfileLease(stream)


@dataclass(frozen=True)
class ProcessResult:
    """Bounded bytes and exit code from an owned process."""

    returncode: int
    stdout: bytes
    stderr: bytes


class OutputLimitExceededError(RuntimeError):
    """The process exceeded the combined stdout/stderr memory budget."""


OutputLimitExceeded = OutputLimitExceededError


async def run_process(
    args: Sequence[str], timeout: float = 30, max_output_bytes: int = 1048576
) -> ProcessResult:
    """Execute literal arguments and kill/reap the owned child on any interrupted operation."""
    if not args or timeout <= 0 or max_output_bytes < 1:
        raise ValueError("Arguments, positive timeout and output limit are required")
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    used = 0

    async def read(stream: asyncio.StreamReader | None) -> bytes:
        nonlocal used
        if stream is None:
            raise RuntimeError("Process stream was not created")
        chunks: list[bytes] = []
        while chunk := await stream.read(min(65536, max_output_bytes + 1)):
            used += len(chunk)
            if used > max_output_bytes:
                raise OutputLimitExceeded("Process output exceeded the configured limit")
            chunks.append(chunk)
        return b"".join(chunks)

    readers = [asyncio.create_task(read(process.stdout)), asyncio.create_task(read(process.stderr))]
    try:
        async with asyncio.timeout(timeout):
            stdout, stderr = await asyncio.gather(*readers)
            return ProcessResult(await process.wait(), stdout, stderr)
    finally:
        for reader in readers:
            reader.cancel()
        if process.returncode is None:
            with suppress(ProcessLookupError):
                process.kill()
        await process.wait()
        await asyncio.gather(*readers, return_exceptions=True)
