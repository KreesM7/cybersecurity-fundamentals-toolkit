"""Protected vault operations; plaintext reveal/export responses are never replay-cached."""

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Header, Request

from backend.mutations import MutationConflictError
from backend.services.vault_service import VaultService
from shared.activity import ActionResult
from shared.vault import (
    CredentialInput,
    CredentialList,
    CredentialReveal,
    CredentialSaved,
    VaultChange,
    VaultExport,
    VaultPassword,
    VaultStatus,
    VaultToken,
    VaultUnlock,
)

router = APIRouter(prefix="/vault", tags=["vault"])
RequestID = Annotated[UUID, Header(alias="X-Request-ID")]
VaultHeader = Annotated[str, Header(alias="X-Vault-Token", min_length=1, max_length=4096)]


def service(request: Request) -> VaultService:
    return cast(VaultService, request.app.state.vault)


@router.get("/status", response_model=VaultStatus)
async def status(request: Request, workspace_id: UUID) -> VaultStatus:
    return await service(request).status(workspace_id)


@router.post("/unlock", response_model=VaultToken)
async def unlock(
    request: Request, workspace_id: UUID, data: VaultUnlock, request_id: RequestID
) -> VaultToken:
    issued: VaultToken | None = None

    async def action() -> ActionResult:
        nonlocal issued
        issued = await service(request).unlock(
            workspace_id, data.password, initialize=data.initialize
        )
        return ActionResult(status="unlocked")

    await request.app.state.mutations.execute(
        workspace_id, request_id, "vault.unlock", data.transport_dump(), action, secret=True
    )
    if issued is None:
        raise MutationConflictError(
            "Unlock response already delivered. Unlock again using a new request ID."
        )
    return issued


@router.post("/lock", response_model=ActionResult)
async def lock(request: Request) -> ActionResult:
    await service(request).lock_all()
    return ActionResult(status="locked")


@router.get("/credentials", response_model=CredentialList)
async def listing(request: Request, workspace_id: UUID, token: VaultHeader) -> CredentialList:
    return await service(request).list(workspace_id, token)


@router.post("/candidates", response_model=CredentialSaved)
async def candidate(
    request: Request,
    workspace_id: UUID,
    token: VaultHeader,
    data: CredentialInput,
    request_id: RequestID,
) -> CredentialSaved:
    await service(request).authorize(workspace_id, token)

    async def action() -> CredentialSaved:
        return await service(request).candidate(workspace_id, token, data)

    value = await request.app.state.mutations.execute(
        workspace_id, request_id, "vault.candidate", data.transport_dump(), action, secret=True
    )
    return CredentialSaved.model_validate(value)


@router.post("/candidates/{identifier}/accept", response_model=CredentialSaved)
async def accept(
    request: Request,
    workspace_id: UUID,
    identifier: UUID,
    token: VaultHeader,
    request_id: RequestID,
) -> CredentialSaved:
    await service(request).authorize(workspace_id, token)

    async def action() -> CredentialSaved:
        return await service(request).accept(workspace_id, token, identifier)

    value = await request.app.state.mutations.execute(
        workspace_id, request_id, "vault.accept", {"id": str(identifier)}, action
    )
    return CredentialSaved.model_validate(value)


@router.delete("/candidates/{identifier}", response_model=ActionResult)
async def discard(
    request: Request,
    workspace_id: UUID,
    identifier: UUID,
    token: VaultHeader,
    request_id: RequestID,
) -> ActionResult:
    await service(request).authorize(workspace_id, token)

    async def action() -> ActionResult:
        await service(request).discard(workspace_id, token, identifier)
        return ActionResult(status="discarded")

    value = await request.app.state.mutations.execute(
        workspace_id, request_id, "vault.discard", {"id": str(identifier)}, action
    )
    return ActionResult.model_validate(value)


@router.post("/credentials/{identifier}/reveal", response_model=CredentialReveal)
async def reveal(
    request: Request, workspace_id: UUID, identifier: UUID, token: VaultHeader, data: VaultPassword
) -> CredentialReveal:
    return await service(request).reveal(workspace_id, token, identifier, data.password)


@router.delete("/credentials/{identifier}", response_model=ActionResult)
async def delete(
    request: Request,
    workspace_id: UUID,
    identifier: UUID,
    token: VaultHeader,
    request_id: RequestID,
) -> ActionResult:
    await service(request).authorize(workspace_id, token)

    async def action() -> ActionResult:
        await service(request).delete(workspace_id, token, identifier)
        return ActionResult(status="deleted")

    value = await request.app.state.mutations.execute(
        workspace_id, request_id, "vault.delete", {"id": str(identifier)}, action
    )
    return ActionResult.model_validate(value)


@router.post("/change-password", response_model=ActionResult)
async def change(
    request: Request,
    workspace_id: UUID,
    token: VaultHeader,
    data: VaultChange,
    request_id: RequestID,
) -> ActionResult:
    await service(request).authorize(workspace_id, token)

    async def action() -> ActionResult:
        await service(request).change_password(
            workspace_id, token, data.password, data.new_password
        )
        return ActionResult(status="password changed; vault locked")

    value = await request.app.state.mutations.execute_external(
        workspace_id, request_id, "vault.change", data.transport_dump(), action
    )
    return ActionResult.model_validate(value)


@router.post("/export", response_model=VaultExport)
async def export(
    request: Request, workspace_id: UUID, token: VaultHeader, data: VaultPassword
) -> VaultExport:
    return VaultExport(content=await service(request).export(workspace_id, token, data.password))
