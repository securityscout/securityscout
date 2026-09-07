"""Global policy read/write. In-process; no extra table."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()


class PoliciesIn(BaseModel):
    scope: dict[str, Any]
    blast_radius: str
    budget: dict[str, Any]
    models: dict[str, Any]
    auto_publish: bool


@router.get("/policies")
def get_policies(request: Request) -> dict[str, Any]:
    return request.app.state.policies


@router.put("/policies")
def put_policies(body: PoliciesIn, request: Request) -> dict[str, Any]:
    stored = body.model_dump()
    request.app.state.policies = stored
    return stored
