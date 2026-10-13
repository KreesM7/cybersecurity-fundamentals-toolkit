"""Owned GUI launch trees; Windows children join a job before the parent runs."""

from __future__ import annotations

import ctypes
import importlib
import os
import signal
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_longlong),
        ("job_time", ctypes.c_longlong),
        ("flags", wintypes.DWORD),
        ("minimum", ctypes.c_size_t),
        ("maximum", ctypes.c_size_t),
        ("active", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority", wintypes.DWORD),
        ("scheduling", wintypes.DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", _BasicLimits),
        ("io", ctypes.c_ulonglong * 6),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process", ctypes.c_size_t),
        ("peak_job", ctypes.c_size_t),
    ]


class _Accounting(ctypes.Structure):
    _fields_ = [
        ("times", ctypes.c_longlong * 4),
        ("faults", wintypes.DWORD),
        ("total", wintypes.DWORD),
        ("active", wintypes.DWORD),
        ("terminated", wintypes.DWORD),
    ]


class _ThreadEntry(ctypes.Structure):
    _fields_ = [
        ("size", wintypes.DWORD),
        ("usage", wintypes.DWORD),
        ("thread_id", wintypes.DWORD),
        ("process_id", wintypes.DWORD),
        ("base_priority", wintypes.LONG),
        ("delta_priority", wintypes.LONG),
        ("flags", wintypes.DWORD),
    ]


class _WindowsJob:
    api: Any
    handle: Any

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise ValueError("Windows Job Objects are unavailable on this platform")
        self.api: Any = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            "SetInformationJobObject": (
                [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD],
                wintypes.BOOL,
            ),
            "QueryInformationJobObject": (
                [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p],
                wintypes.BOOL,
            ),
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "CreateToolhelp32Snapshot": ([wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
            "Thread32First": ([wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)], wintypes.BOOL),
            "Thread32Next": ([wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)], wintypes.BOOL),
            "OpenThread": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "ResumeThread": ([wintypes.HANDLE], wintypes.DWORD),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = _ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        if not self.api.SetInformationJobObject(
            self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            self.api.CloseHandle(self.handle)
            raise ctypes.WinError(ctypes.get_last_error())

    def attach_and_resume(self, pid: int) -> None:
        if sys.platform != "win32":
            raise ValueError("Windows Job Objects are unavailable on this platform")
        process = self.api.OpenProcess(0x0100 | 0x0001, False, pid)
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self.api.AssignProcessToJobObject(self.handle, process):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.api.CloseHandle(process)
        snapshot = self.api.CreateToolhelp32Snapshot(0x0004, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = _ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            present = self.api.Thread32First(snapshot, ctypes.byref(entry))
            while present:
                if entry.process_id == pid:
                    thread = self.api.OpenThread(0x0002, False, entry.thread_id)
                    if not thread:
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        if self.api.ResumeThread(thread) == 0xFFFFFFFF:
                            raise ctypes.WinError(ctypes.get_last_error())
                    finally:
                        self.api.CloseHandle(thread)
                    return
                present = self.api.Thread32Next(snapshot, ctypes.byref(entry))
            raise ValueError("Owned GUI launch thread disappeared before resume")
        finally:
            self.api.CloseHandle(snapshot)

    def alive(self) -> bool:
        if sys.platform != "win32":
            raise ValueError("Windows Job Objects are unavailable on this platform")
        if not self.handle:
            return False
        data = _Accounting()
        if not self.api.QueryInformationJobObject(
            self.handle, 1, ctypes.byref(data), ctypes.sizeof(data), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(data.active)

    def close(self) -> None:
        if sys.platform != "win32":
            raise ValueError("Windows Job Objects are unavailable on this platform")
        if not self.handle:
            return
        if not self.api.TerminateJobObject(self.handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        deadline = time.monotonic() + 4
        while self.alive():
            if time.monotonic() >= deadline:
                raise ValueError("GUI children have not exited; ownership is retained")
            time.sleep(0.02)
        if not self.api.CloseHandle(self.handle):
            raise ctypes.WinError(ctypes.get_last_error())
        self.handle = None


class NativeGUI:
    def __init__(self, argv: list[str], directory: Path) -> None:
        if not argv or any("\0" in value for value in argv) or not directory.is_dir():
            raise ValueError("Valid GUI arguments and working directory are required")
        self.closed = False
        self._psutil: Any = importlib.import_module("psutil")
        self._job = _WindowsJob() if os.name == "nt" else None
        self._process: subprocess.Popen[bytes] | None = None
        try:
            self._process = subprocess.Popen(
                argv,
                cwd=directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=0x0004 | 0x08000000 if self._job else 0,
                start_new_session=self._job is None,
            )
            if self._job:
                self._job.attach_and_resume(self._process.pid)
        except BaseException:
            if self._process is not None:
                self._process.kill()
                self._process.wait()
            if self._job:
                self._job.close()
            raise

    def _members(self) -> list[Any]:
        if sys.platform == "win32":
            raise ValueError("POSIX session enumeration is not supported on Windows")
        assert self._process is not None
        members = []
        for process in self._psutil.process_iter():
            try:
                if os.getsid(process.pid) == self._process.pid and (
                    process.status() != self._psutil.STATUS_ZOMBIE
                ):
                    members.append(process)
            except (ProcessLookupError, PermissionError, self._psutil.NoSuchProcess):
                continue
        return members

    def alive(self) -> bool:
        if self.closed:
            return False
        assert self._process is not None
        self._process.poll()  # Reap the root while preserving child ownership.
        return self._job.alive() if self._job else bool(self._members())

    def close(self) -> None:
        if self.closed:
            return
        assert self._process is not None
        if self._job:
            self._job.close()
        else:
            if sys.platform == "win32":
                raise ValueError("Windows GUI ownership requires a Job Object")
            # The session ID cannot be reused while an owned member still exists.
            for sig in (signal.SIGTERM, signal.SIGKILL):
                for process in self._members():
                    try:
                        process.send_signal(sig)
                    except self._psutil.NoSuchProcess:
                        pass
                deadline = time.monotonic() + 2
                while self._members() and time.monotonic() < deadline:
                    time.sleep(0.02)
            if self._members():
                raise ValueError("GUI children have not exited; ownership is retained")
        self._process.wait(timeout=2)
        self.closed = True
