"""Run enqueue, cancel, and run events."""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from api.app import ApiError, error_response
from api.routes_engagements import get_engagement
from triage import db

router = APIRouter()

RUN_SPANS_CAP = 200


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


def _spans(conn: Any, run_id: str) -> list[dict[str, Any]]:
    """The newest RUN_SPANS_CAP spans of one run, returned oldest-first.

    A span with a null `t` sorts last under DESC, so an over-cap run drops it
    first and the console reads it as the oldest row.
    """
    rows = conn.execute(
        "SELECT id, agent, tool, args_hash, result_sha256, t FROM tool_spans "
        "WHERE run_id = ? ORDER BY t DESC, id DESC LIMIT ?",
        (run_id, RUN_SPANS_CAP),
    ).fetchall()
    return [dict(row) for row in reversed(rows)]


def _budget_limit_usd(conn: Any, engagement_id: str) -> float | None:
    """The engagement's `budget_usd` ceiling, or None when there isn't one.

    Anything that is not a positive number — malformed `policy_json`, a
    non-object policy, a bool, a string, zero — reads as no ceiling, so the
    meter goes indeterminate instead of showing a guessed one.
    """
    row = conn.execute(
        "SELECT policy_json FROM engagements WHERE id = ?", (engagement_id,)
    ).fetchone()
    if row is None:
        return None
    try:
        policy = json.loads(row["policy_json"])
    except ValueError:
        return None
    limit = policy.get("budget_usd") if isinstance(policy, dict) else None
    if isinstance(limit, bool) or not isinstance(limit, (int, float)):
        return None
    return float(limit) if limit > 0 else None


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
    """One payload for the whole console.

    The evidence timeline rides the poll `GET /runs/{id}` already carries; a
    second query on that route would double the request the UI makes each
    second.
    """
    with db.session(request.app.state.db_path) as conn:
        row = _get_run(conn, run_id)
        return {
            **_run(row),
            "budget_limit_usd": _budget_limit_usd(conn, row["engagement_id"]),
            "spans": _spans(conn, run_id),
        }


@router.post("/runs/{run_id}/cancel")
def cancel_run(run_id: str, request: Request) -> dict[str, str]:
    with db.session(request.app.state.db_path) as conn:
        _get_run(conn, run_id)
        conn.execute("UPDATE runs SET status = 'cancelled' WHERE id = ?", (run_id,))
    return {"id": run_id, "status": "cancelled"}


@router.get("/runs/{run_id}/events")
def run_events(run_id: str, request: Request) -> JSONResponse:
    """No worker emits envelopes yet, so every existing run is unavailable.

    An empty 200 looks like a dropped stream and `EventSource` reconnects on
    it forever; a 503 is a permanent failure the client must act on.
    """
    with db.session(request.app.state.db_path) as conn:
        _get_run(conn, run_id)

    return error_response(
        503,
        "unavailable",
        "run event stream is not available yet",
        headers={"Retry-After": "5"},
    )
