"""Acceptance tests for the org scheduler: dry-run enqueue + kill switch."""

from __future__ import annotations

from pathlib import Path

import pytest

from triage import db, scheduler


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    p = tmp_path / "scheduler-test.db"
    db.init_schema(p)
    return p


def _make_engagement(db_path: Path, engagement_id: str = "eng_1") -> None:
    with db.session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO engagements (id, name, org, policy_json, created_at)
            VALUES (?, 'acme-web', 'acme', '{}', '2026-09-12T00:00:00+00:00')
            """,
            (engagement_id,),
        )


def _statuses(db_path: Path, run_ids: list[str]) -> set[str]:
    placeholders = ",".join("?" for _ in run_ids)
    with db.session(db_path) as conn:
        rows = conn.execute(
            f"SELECT status FROM runs WHERE id IN ({placeholders})", run_ids
        ).fetchall()
    return {r["status"] for r in rows}


def test_dry_run_enqueues_two_repos(db_path: Path) -> None:
    _make_engagement(db_path)
    repos = [
        {"repo": "acme/one", "sha": "1" * 40},
        {"repo": "acme/two", "sha": "2" * 40},
    ]

    result = scheduler.enqueue(repos, db_path=db_path, engagement_id="eng_1")

    assert len(result["run_ids"]) == 2
    assert _statuses(db_path, result["run_ids"]) == {"queued"}


def test_kill_cancels_both(db_path: Path) -> None:
    _make_engagement(db_path)
    repos = [
        {"repo": "acme/one", "sha": "1" * 40},
        {"repo": "acme/two", "sha": "2" * 40},
    ]
    enqueued = scheduler.enqueue(repos, db_path=db_path, engagement_id="eng_1")

    result = scheduler.kill(db_path=db_path)

    assert result["cancelled"] == 2
    assert _statuses(db_path, enqueued["run_ids"]) == {"cancelled"}


def test_kill_leaves_done_alone(db_path: Path) -> None:
    _make_engagement(db_path)
    with db.session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO runs (
              id, engagement_id, mode, playbook, repo, sha, status, budget_spent_usd
            ) VALUES ('done_run', 'eng_1', 'hunt', 'web-app.v1', 'acme/x', ?, 'done', 0)
            """,
            ("3" * 40,),
        )

    result = scheduler.kill(db_path=db_path)

    assert result["cancelled"] == 0
    assert _statuses(db_path, ["done_run"]) == {"done"}


def test_enqueue_unknown_engagement_raises(db_path: Path) -> None:
    with pytest.raises(ValueError):
        scheduler.enqueue(
            [{"repo": "acme/one", "sha": "1" * 40}],
            db_path=db_path,
            engagement_id="nope",
        )


def test_enqueue_empty_repos_raises(db_path: Path) -> None:
    _make_engagement(db_path)
    with pytest.raises(ValueError):
        scheduler.enqueue([], db_path=db_path, engagement_id="eng_1")
