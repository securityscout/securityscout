"""Engagement CRUD."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

from api.app import ApiError
from triage import db

router = APIRouter()


class EngagementIn(BaseModel):
    name: str
    org: str
    policy_json: dict[str, Any] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _engagement(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "org": row["org"],
        "policy_json": json.loads(row["policy_json"]),
        "created_at": row["created_at"],
    }


@router.get("/engagements")
def list_engagements(request: Request) -> dict[str, list[dict[str, Any]]]:
    with db.session(request.app.state.db_path) as conn:
        rows = conn.execute("SELECT * FROM engagements ORDER BY created_at").fetchall()
    return {"engagements": [_engagement(r) for r in rows]}


@router.post("/engagements", status_code=201)
def create_engagement(body: EngagementIn, request: Request) -> dict[str, Any]:
    eng_id = uuid.uuid4().hex
    created_at = _now()
    policy = json.dumps(body.policy_json)
    with db.session(request.app.state.db_path) as conn:
        conn.execute(
            "INSERT INTO engagements (id, name, org, policy_json, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (eng_id, body.name, body.org, policy, created_at),
        )
        row = conn.execute("SELECT * FROM engagements WHERE id = ?", (eng_id,)).fetchone()
    return _engagement(row)


@router.get("/engagements/{engagement_id}")
def get_engagement(engagement_id: str, request: Request) -> dict[str, Any]:
    with db.session(request.app.state.db_path) as conn:
        row = conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
        ).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "engagement not found")
    return _engagement(row)
