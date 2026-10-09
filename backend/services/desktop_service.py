"""Private preferences and an optional bounded, quiet release check."""

import asyncio
import json
import re
from pathlib import Path

import httpx

from backend.platform_utils import assert_private_path, atomic_private_write
from shared.desktop import DesktopSettings, UpdateNotice

REPOSITORY = "KreesM7/cybersecurity-fundamentals-toolkit"
RELEASE_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASE_PAGE = f"https://github.com/{REPOSITORY}/releases/tag/"


def stable_version(value: str) -> tuple[int, ...] | None:
    if re.fullmatch(r"v?(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})", value):
        return tuple(int(x) for x in value.removeprefix("v").split("."))
    return None


class DesktopService:
    def __init__(self, profile: Path) -> None:
        self.path = profile / "desktop.json"
        self.settings = DesktopSettings()
        self.notice = UpdateNotice()
        self.etag = ""
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self.path.exists():
            assert_private_path(self.path)
            try:
                if self.path.stat().st_size > 16384:
                    raise ValueError("Settings file exceeds limit")
                data = json.loads(await asyncio.to_thread(self.path.read_text, "utf-8"))
                self.settings = DesktopSettings.model_validate(data["settings"])
                self.etag = str(data.get("etag", ""))[:512]
                notice = UpdateNotice.model_validate(data.get("notice", {}))
                version = stable_version(notice.version)
                if version and version > (2, 0, 0) and notice.url == RELEASE_PAGE + notice.version:
                    self.notice = notice
            except (ValueError, TypeError, KeyError):
                # Only non-secret preferences are reset; application data is untouched.
                self.settings = DesktopSettings()
                self.etag = ""
        self.schedule_check()

    def schedule_check(self) -> None:
        if self.settings.check_updates and (self._task is None or self._task.done()):
            self._task = asyncio.create_task(self.check())

    async def _save(self) -> None:
        data = json.dumps(
            {
                "settings": self.settings.model_dump(),
                "etag": self.etag,
                "notice": self.notice.model_dump(),
            }
        ).encode()
        await asyncio.to_thread(atomic_private_write, self.path, data)

    async def update(self, value: DesktopSettings) -> DesktopSettings:
        async with self._lock:
            previous = self.settings
            self.settings = value.model_copy()
            try:
                await self._save()
            except BaseException:
                self.settings = previous
                raise
        if not value.check_updates and self._task:
            self._task.cancel()
        elif not previous.check_updates:
            self.schedule_check()
        return self.settings.model_copy()

    def visible_notice(self) -> UpdateNotice:
        if (
            not self.settings.check_updates
            or self.settings.dismissed_version == self.notice.version
        ):
            return UpdateNotice()
        return self.notice.model_copy()

    async def check(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if not self.settings.check_updates:
            return
        try:
            async with asyncio.timeout(5):
                headers = {"Accept": "application/vnd.github+json", "User-Agent": "Toolkit/2.0.0"}
                if self.etag:
                    headers["If-None-Match"] = self.etag
                async with httpx.AsyncClient(
                    verify=True,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=5,
                    transport=transport,
                ) as client:
                    async with client.stream("GET", RELEASE_API, headers=headers) as response:
                        if response.status_code != 200:
                            return
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > 65536:
                                return
                        result = json.loads(body)
                        if (
                            not isinstance(result, dict)
                            or result.get("draft") is not False
                            or result.get("prerelease") is not False
                        ):
                            return
                        tag = result.get("tag_name", "")
                        version = stable_version(tag) if isinstance(tag, str) else None
                        if not version:
                            return
                        async with self._lock:
                            if not self.settings.check_updates:
                                return
                            self.notice = (
                                UpdateNotice(version=tag, url=RELEASE_PAGE + tag)
                                if version > (2, 0, 0)
                                else UpdateNotice()
                            )
                            self.etag = response.headers.get("etag", "")[:512]
                            await self._save()
        except (httpx.HTTPError, TimeoutError, ValueError, OSError):
            pass  # Offline, malformed, rate limited and absent releases remain quiet.

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
