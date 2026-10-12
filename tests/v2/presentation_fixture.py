"""Offline desktop fixture: records intents and never connects or executes commands."""

from uuid import uuid4

from PyQt6.QtCore import QObject

from frontend.viewmodels.app_vm import AppViewModel


class PresentationModel(AppViewModel):
    def __init__(self):
        QObject.__init__(self)
        self.workspace_id = uuid4()
        self.vault_token = None
        self.calls = []

    def record(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return uuid4()

    get = mutate = refresh_health = refresh_tools = refresh_interfaces = record
    refresh_workspaces = targets = module_library = watch_events = record
    close = clear = clear_vault_state = module_detail = search_modules = record
    favorite = transfer_target = launch_module = submit = cancel = record
    vault_request = invalidate = save_artifact = record
