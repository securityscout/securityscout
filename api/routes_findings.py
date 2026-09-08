"""Finding list, case file, replay enqueue, and review."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

from api.app import ApiError
from triage import db
from triage.status import (
    REVIEW_TARGET,
    IllegalTransition,
    TransitionConflict,
    cas_status,
)

router = APIRouter()

_FINDING_SELECT = (
    "f.id, f.repo_url, f.sha, f.rule_id, f.file, f.line, "
    "f.status, f.run_id, f.source_kind"
)


class ReviewIn(BaseModel):
    action: str


def _finding(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "repo_url": row["repo_url"],
        "sha": row["sha"],
        "rule_id": row["rule_id"],
        "file": row["file"],
        "line": row["line"],
        "status": row["status"],
        "run_id": row["run_id"],
        "source_kind": row["source_kind"],
    }


def _get_finding(conn: Any, finding_id: str) -> Any:
    row = conn.execute(
        f"SELECT {_FINDING_SELECT} FROM findings f WHERE f.id = ?",
        (finding_id,),
    ).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "finding not found")
    return row


@router.get("/findings")
def list_findings(
    request: Request,
    engagement_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    repo: str | None = Query(default=None),
) -> dict[str, list[dict[str, Any]]]:
    sql = (
        f"SELECT {_FINDING_SELECT} FROM findings f "
        "LEFT JOIN runs r ON r.id = f.run_id WHERE 1=1"
    )
    params: list[Any] = []
    if engagement_id is not None:
        sql += " AND r.engagement_id = ?"
        params.append(engagement_id)
    if status is not None:
        sql += " AND f.status = ?"
        params.append(status)
    if repo is not None:
        sql += " AND (r.repo = ? OR f.repo_url LIKE ?)"
        params.extend([repo, f"%{repo}%"])
    with db.session(request.app.state.db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return {"findings": [_finding(r) for r in rows]}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, request: Request) -> dict[str, Any]:
    with db.session(request.app.state.db_path) as conn:
        return _finding(_get_finding(conn, finding_id))


@router.post("/findings/{finding_id}/replay", status_code=202)
def replay_finding(finding_id: str, request: Request) -> dict[str, str]:
    with db.session(request.app.state.db_path) as conn:
        _get_finding(conn, finding_id)
    return {"finding_id": finding_id, "replay_status": "queued"}


@router.post("/findings/{finding_id}/review")
def review_finding(finding_id: str, body: ReviewIn, request: Request) -> dict[str, str]:
    target = REVIEW_TARGET.get(body.action)
    if target is None:
        raise ApiError(400, "invalid_request", f"unknown action {body.action}")
    with db.session(request.app.state.db_path) as conn:
        row = _get_finding(conn, finding_id)
        try:
            cas_status(conn, finding_id, row["status"], target)
        except IllegalTransition as exc:
            raise ApiError(409, "illegal_transition", str(exc)) from exc
        except TransitionConflict as exc:
            raise ApiError(409, "conflict", str(exc)) from exc
    return {"id": finding_id, "status": target}
