"""Desktop state and typed actions share one asynchronous client thread."""

import json
import ssl
from urllib.parse import urlencode
from uuid import UUID

import httpx
from pydantic import BaseModel, RootModel
from PyQt6.QtCore import QObject, pyqtSignal

from frontend.viewmodels.tools_vm import ToolsViewModel
from shared.modules import (
    FavoriteChange,
    ModuleDetail,
    ModuleLaunch,
    ModuleLibrary,
    ModuleRun,
    ModuleSearch,
)
from shared.schemas import SchemaModel
from shared.workspaces import TargetTransfer, TargetView, WorkspaceView


class AppViewModel(ToolsViewModel):
    state_changed = pyqtSignal(str, object)
    action_error = pyqtSignal(str, str)

    def __init__(
        self,
        base_url: str,
        ssl_context: ssl.SSLContext,
        instance_token: str,
        *,
        transport: httpx.ASGITransport | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(base_url, ssl_context, instance_token, transport=transport, parent=parent)
        self.workspace_id: UUID | None = None
        self._actions: dict[UUID, str] = {}
        self._latest: dict[str, UUID] = {}
        self.mutation_completed.connect(self._result)
        self.request_failed.connect(self._action_failed)
        self.message_received.connect(self._event)

    def get(self, key: str, path: str, model: type[BaseModel]) -> None:
        identifier = self.run_get(path, model)
        self._actions[identifier] = key
        self._latest[key] = identifier

    def mutate(
        self,
        key: str,
        method: str,
        path: str,
        model: type[BaseModel],
        body: SchemaModel | None = None,
    ) -> None:
        identifier = self.run_mutation(method, path, model, body)
        self._actions[identifier] = key
        # Mutations are never retried or discarded merely because another action follows.

    def _result(self, identifier: object, value: object) -> None:
        if not isinstance(identifier, UUID):
            return
        key = self._actions.pop(identifier, None)
        if key is None or (key in self._latest and self._latest[key] != identifier):
            return
        if key == "workspaces" and isinstance(value, RootModel):
            active = next((row.id for row in value.root if row.active), None)
            if active != self.workspace_id:
                self.workspace_id = active
                self.state_changed.emit("workspace", active)
        self.state_changed.emit(key, value)

    def _action_failed(self, identifier: object, message: str) -> None:
        if isinstance(identifier, UUID):
            key = self._actions.pop(identifier, None)
            if key:
                self.action_error.emit(key, message)

    def _event(self, value: object) -> None:
        if not isinstance(value, (str, bytes)):
            return
        try:
            event = json.loads(value)
        except (ValueError, TypeError):
            return
        if not isinstance(event, dict):
            return
        self.state_changed.emit("event", event)
        if event.get("topic") == "workspace-activated":
            self.refresh_workspaces()

    def refresh_workspaces(self) -> None:
        self.get("workspaces", "/api/v1/workspaces/", RootModel[list[WorkspaceView]])

    def search_modules(self, query: str, kind: str, rank: str, platform: str) -> None:
        self.get(
            "module-search",
            "/api/v1/modules/search?"
            + urlencode(dict(query=query, kind=kind, rank=rank, platform=platform)),
            ModuleSearch,
        )

    def module_detail(self, path: str, *, payload: bool = False) -> None:
        self.get(
            "payload-detail" if payload else "module-detail",
            "/api/v1/modules/info?" + urlencode({"path": path}),
            ModuleDetail,
        )

    def module_library(self) -> None:
        if self.workspace_id:
            self.get(
                "module-library",
                f"/api/v1/modules/library?workspace_id={self.workspace_id}",
                ModuleLibrary,
            )

    def favorite(self, path: str, enabled: bool) -> None:
        if self.workspace_id:
            self.mutate(
                "module-favorite",
                "POST",
                f"/api/v1/modules/favorites?workspace_id={self.workspace_id}",
                ModuleLibrary,
                FavoriteChange(path=path, enabled=enabled),
            )

    def launch_module(self, value: ModuleRun) -> None:
        self.mutate("module-launch", "POST", "/api/v1/modules/run", ModuleLaunch, value)

    def targets(self) -> None:
        self.get("targets", "/api/v1/targets/", RootModel[list[TargetView]])

    def transfer_target(self, identifier: UUID) -> None:
        self.mutate(
            "target-transfer", "POST", f"/api/v1/targets/{identifier}/use-as-rhosts", TargetTransfer
        )
