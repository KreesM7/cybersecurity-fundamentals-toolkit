"""Framework lifecycle shared by RPC and the separately supervised PTY adapter."""

from __future__ import annotations

import asyncio
import json
import re
import ssl
from collections import deque
from pathlib import Path
from uuid import uuid4

import keyring
from pydantic import JsonValue, SecretStr

from backend.events import EventHub
from backend.platform_utils import atomic_private_write, framework_host_argv
from backend.services.pty_transport import PtyTransport
from backend.services.rpc_transport import FrameworkTransport, RpcFailure, RpcTransport
from shared.framework import ConnectionStatus, RpcConnect

MODULE_TYPES = {
    "exploit": "exploits",
    "auxiliary": "auxiliary",
    "post": "post",
    "payload": "payloads",
    "encoder": "encoders",
    "nop": "nops",
    "evasion": "evasion",
}


def module_parts(path: str) -> tuple[str, str]:
    parts = path.split("/", 1)
    if (
        len(parts) != 2
        or parts[0] not in MODULE_TYPES
        or len(path) > 200
        or not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", parts[1])
    ):
        raise ValueError("Choose a valid framework module path.")
    return parts[0], parts[1]


class MetasploitService:
    def __init__(self, profile: Path, events: EventHub) -> None:
        self.profile, self.events = profile, events
        self.transport: FrameworkTransport | None = None
        self._status = ConnectionStatus()
        self._connection_lock = asyncio.Lock()
        self._reconnect_task: asyncio.Task[None] | None = None
        self._settings: RpcConnect | None = None
        self._password: SecretStr | None = None
        self._expected_identity: str | None = None
        self._closed = False
        self.console_lines: deque[str] = deque(maxlen=10000)

    def status(self) -> ConnectionStatus:
        return self._status.model_copy()

    async def _state(self, message: str, connected: bool = False) -> None:
        self._status = ConnectionStatus(
            state=(
                ("PTYFallback" if isinstance(self.transport, PtyTransport) else "RPCConnected")
                if connected
                else "Offline"
            ),
            instance_id=self._expected_identity,
            endpoint=self._status.endpoint,
            message=message,
            owned=isinstance(self.transport, PtyTransport),
        )
        await self.events.publish("connection", self._status.model_dump(mode="json"))

    async def connect(self, settings: RpcConnect) -> ConnectionStatus:
        async with self._connection_lock:
            if self.transport is not None or self._reconnect_task is not None:
                raise ValueError("Disconnect the current framework before connecting another.")
            host = f"[{settings.host}]" if ":" in settings.host else settings.host
            url = f"https://{host}:{settings.port}/api/"
            try:
                context = ssl.create_default_context(cadata=settings.ca_pem)
            except ssl.SSLError as exc:
                raise ValueError("Supply the valid public RPC certificate in PEM format.") from exc
            password = settings.password
            account = f"{url}|{settings.username}"
            if password is None:
                try:
                    saved = await asyncio.to_thread(keyring.get_password, "Toolkit-MSF", account)
                except keyring.errors.KeyringError as exc:
                    raise RpcFailure(
                        "OS keyring unavailable; enter the RPC password for this run."
                    ) from exc
                if not saved:
                    raise RpcFailure("Enter an RPC password; none is stored in the OS keyring.")
                password = SecretStr(saved)
            candidate = RpcTransport(url, context)
            try:
                identity = await candidate.login(settings.username, password.get_secret_value())
                if settings.remember_password:
                    try:
                        await asyncio.to_thread(
                            keyring.set_password,
                            "Toolkit-MSF",
                            account,
                            password.get_secret_value(),
                        )
                    except keyring.errors.KeyringError as exc:
                        raise RpcFailure(
                            "Unlock a supported OS keyring to remember this password."
                        ) from exc
                public_settings = settings.model_dump(mode="json", exclude={"password"})
                atomic_private_write(
                    self.profile / "rpc.json", json.dumps(public_settings).encode()
                )
            except BaseException:
                await candidate.close()
                raise
            self.transport = candidate
            self._expected_identity = identity
            self._settings = settings.model_copy(update={"password": None})
            self._password = password
            self._status = ConnectionStatus(endpoint=url)
            await self._state("Connected using verified TLS and a temporary token.", True)
            return self.status()

    async def connect_fallback(self, *, confirmed: bool) -> ConnectionStatus:
        if not confirmed:
            raise ValueError("Confirm starting your dedicated owned Metasploit console.")
        async with self._connection_lock:
            if self.transport is not None or self._reconnect_task is not None:
                raise ValueError("Disconnect the current framework before starting fallback.")
            token = uuid4().hex
            candidate = PtyTransport(
                framework_host_argv(token),
                lambda line: self.console_lines.append(self.events.redactor.text(line)),
                cancel_argv=framework_host_argv(token, cancel=True),
            )
            await candidate.start()
            self.transport = candidate
            self._expected_identity = candidate.identity
            self._status = ConnectionStatus(endpoint="Toolkit-MSF owned PTY")
            await self._state("Connected to the owned structured terminal bridge.", True)
            return self.status()

    async def shutdown_check(self) -> bool:
        if not isinstance(self.transport, PtyTransport):
            return False
        try:
            return bool(
                await self.transport.call("session.list") or await self.transport.call("job.list")
            )
        except RpcFailure:
            return True

    async def disconnect(self, *, confirmed: bool = False) -> ConnectionStatus:
        async with self._connection_lock:
            if not confirmed and await self.shutdown_check():
                raise ValueError(
                    "Confirm termination of active or uncertain owned framework activity."
                )
            task, self._reconnect_task = self._reconnect_task, None
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            transport, self.transport = self.transport, None
            self._password = None
            self._settings = None
            if transport is not None:
                await transport.close()
            self._expected_identity = None
            await self._state("Disconnected. Externally managed framework remains running.")
            return self.status()

    async def _reconnect(self) -> None:
        delay = 1
        while not self._closed and self._settings is not None and self._password is not None:
            await asyncio.sleep(delay)
            settings = self._settings
            candidate = RpcTransport(
                self._status.endpoint, ssl.create_default_context(cadata=settings.ca_pem)
            )
            try:
                identity = await candidate.login(
                    settings.username, self._password.get_secret_value()
                )
                if identity != self._expected_identity:
                    await candidate.close()
                    await self._state(
                        "Framework instance changed. Reconcile old activity, "
                        "then reconnect explicitly."
                    )
                    return
                previous, self.transport = self.transport, candidate
                if previous is not None:
                    await previous.close()
                await self._state("Reconnected to the same framework instance.", True)
                return
            except asyncio.CancelledError:
                await candidate.close()
                raise
            except (RpcFailure, OSError, ValueError):
                await candidate.close()
            delay = min(delay * 2, 30)

    async def call(self, method: str, args: list[JsonValue] | None = None) -> dict[str, JsonValue]:
        transport = self.transport
        if transport is None or self._status.state == "Offline":
            raise RpcFailure("Framework is offline. Connect in Settings.")
        try:
            return await transport.call(method, args)
        except RpcFailure:
            await self._state("Connection interrupted. Commands are not repeated automatically.")
            if self._reconnect_task is None or self._reconnect_task.done():
                self._reconnect_task = asyncio.create_task(self._reconnect())
            raise

    async def get_modules(self) -> list[str]:
        result: list[str] = []
        for kind, endpoint in MODULE_TYPES.items():
            reply = await self.call(f"module.{endpoint}")
            names = reply.get("modules")
            if not isinstance(names, list):
                raise RpcFailure("Framework returned invalid module metadata.")
            for name in names:
                if not isinstance(name, str):
                    raise RpcFailure("Framework returned an invalid module name.")
                path = f"{kind}/{name}"
                module_parts(path)
                result.append(path)
                if len(result) > 30000:
                    raise RpcFailure("Framework module catalog exceeded30000 entries.")
        return result

    async def get_module_info(self, path: str) -> dict[str, JsonValue]:
        kind, name = module_parts(path)
        return {
            "path": path,
            "info": await self.call("module.info", [kind, name]),
            "options": await self.call("module.options", [kind, name]),
        }

    async def run_module(
        self, path: str, options: dict[str, JsonValue], *, owned: bool
    ) -> dict[str, JsonValue]:
        kind, name = module_parts(path)
        if not owned:
            raise ValueError("Confirm ownership or permission before running a module.")
        return await self.call("module.execute", [kind, name, options])

    async def get_sessions(self) -> dict[str, JsonValue]:
        return await self.call("session.list")

    async def get_jobs(self) -> dict[str, JsonValue]:
        return await self.call("job.list")

    async def kill_job(self, identifier: str) -> dict[str, JsonValue]:
        return await self.call("job.stop", [identifier])

    async def kill_session(self, identifier: str) -> dict[str, JsonValue]:
        return await self.call("session.stop", [identifier])

    async def interact_session(
        self, identifier: str, kind: str, command: str | None = None
    ) -> dict[str, JsonValue]:
        if kind not in {"shell", "meterpreter"} or len(identifier) > 100:
            raise ValueError("Unsupported session type or identifier.")
        operation = "read" if command is None else "write"
        args: list[JsonValue] = [identifier]
        if command is not None:
            if len(command) > 65536:
                raise ValueError("Session command exceeds65536 characters.")
            args.append(command)
        return await self.call(f"session.{kind}_{operation}", args)

    async def close(self) -> None:
        self._closed = True
        await self.disconnect(confirmed=True)
