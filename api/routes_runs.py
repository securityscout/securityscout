"""Run enqueue, cancel, and event stream."""

from __future__ import annotations

import uuid
from typing import Any, AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from api.app import ApiError
from api.routes_engagements import get_engagement
from triage import db

router = APIRouter()


class RunIn(BaseModel):
    mode: str
    playbook: str
    repo: str
    sha: str
    target_url: str | None = None


def _run(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "engagement_id": row["engagement_id"],
        "mode": row["mode"],
        "playbook": row["playbook"],
        "repo": row["repo"],
        "sha": row["sha"],
        "target_url": row["target_url"],
        "status": row["status"],
        "budget_spent_usd": row["budget_spent_usd"],
        "started_at": row["started_at"],
        "ended_at": row["ended_at"],
    }


def _get_run(conn: Any, run_id: str) -> Any:
    row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "run not found")
    return row


@router.get("/engagements/{engagement_id}/runs")
def list_runs(engagement_id: str, request: Request) -> dict[str, list[dict[str, Any]]]:
    get_engagement(engagement_id, request)
    with db.session(request.app.state.db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM runs WHERE engagement_id = ?", (engagement_id,)
        ).fetchall()
    return {"runs": [_run(r) for r in rows]}


@router.post("/engagements/{engagement_id}/runs", status_code=201)
def create_run(engagement_id: str, body: RunIn, request: Request) -> dict[str, Any]:
    get_engagement(engagement_id, request)
    run_id = uuid.uuid4().hex
    with db.session(request.app.state.db_path) as conn:
        conn.execute(
            """
            INSERT INTO runs (
              id, engagement_id, mode, playbook, repo, sha, target_url, status, budget_spent_usd
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 0)
            """,
            (
                run_id,
                engagement_id,
                body.mode,
                body.playbook,
                body.repo,
                body.sha,
                body.target_url,
            ),
        )
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    return _run(row)


@router.get("/runs/{run_id}")
def get_run(run_id: str, request: Request) -> dict[str, Any]:
    with db.session(request.app.state.db_path) as conn:
        return _run(_get_run(conn, run_id))


@router.post("/runs/{run_id}/cancel")
def cancel_run(run_id: str, request: Request) -> dict[str, str]:
    with db.session(request.app.state.db_path) as conn:
        _get_run(conn, run_id)
        conn.execute("UPDATE runs SET status = 'cancelled' WHERE id = ?", (run_id,))
    return {"id": run_id, "status": "cancelled"}


@router.get("/runs/{run_id}/events")
def run_events(run_id: str, request: Request) -> StreamingResponse:
    with db.session(request.app.state.db_path) as conn:
        _get_run(conn, run_id)

    async def _empty() -> AsyncIterator[bytes]:
        if False:  # pragma: no cover
            yield b""

    return StreamingResponse(_empty(), media_type="text/event-stream")
