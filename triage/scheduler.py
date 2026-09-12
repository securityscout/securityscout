"""Org-wide hunt scheduler: dry-run enqueue and the kill switch (library).

This slice only ever writes `queued` rows — no worker moves a run to
`running`, so `enqueue` does not spawn anything regardless of `dry_run`.
A real dispatcher is a later slice's job.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from triage import db


def enqueue(
    repos: list[dict[str, str]],
    *,
    db_path: Path | str,
    engagement_id: str,
    dry_run: bool = True,
) -> dict[str, list[str]]:
    if not dry_run:
        raise NotImplementedError("live enqueue has no worker yet; call with dry_run=True")
    if not repos:
        raise ValueError("repos must not be empty")

    run_ids: list[str] = []
    with db.session(db_path) as conn:
        engagement = conn.execute(
            "SELECT id FROM engagements WHERE id = ?", (engagement_id,)
        ).fetchone()
        if engagement is None:
            raise ValueError(f"unknown engagement_id: {engagement_id}")

        for repo in repos:
            run_id = uuid.uuid4().hex
            conn.execute(
                """
                INSERT INTO runs (
                  id, engagement_id, mode, playbook, repo, sha, status, budget_spent_usd
                ) VALUES (?, ?, 'hunt', 'web-app.v1', ?, ?, 'queued', 0)
                """,
                (run_id, engagement_id, repo["repo"], repo["sha"]),
            )
            run_ids.append(run_id)

    return {"run_ids": run_ids}


def kill(*, db_path: Path | str) -> dict[str, int]:
    with db.session(db_path) as conn:
        cursor = conn.execute(
            "UPDATE runs SET status = 'cancelled' WHERE status IN ('queued', 'running')"
        )
        cancelled = cursor.rowcount

    return {"cancelled": cancelled}
