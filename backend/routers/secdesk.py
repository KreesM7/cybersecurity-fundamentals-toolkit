"""Authenticated, passive environment checks executed off the event loop."""

import asyncio

from fastapi import APIRouter, HTTPException

from toolkit.secdesk.registry import Check, doctor, load_registry

router = APIRouter(prefix="/secdesk", tags=["secdesk"])


@router.get("/doctor", response_model=list[Check])
async def environment() -> list[Check]:
    def inspect() -> list[Check]:
        return [doctor(tool) for tool in load_registry()]

    try:
        return await asyncio.to_thread(inspect)
    except (OSError, ValueError) as error:
        raise HTTPException(
            503, "Tool manifests could not be loaded. Check installation."
        ) from error
