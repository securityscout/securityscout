"""Acceptance tests for triage/gateway.py."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

import pytest

from triage import db, gateway


@pytest.fixture()
def run_db(tmp_path: Path) -> Path:
    p = tmp_path / "gateway-test.db"
    db.init_schema(p)
    with db.session(p) as conn:
        conn.execute(
            "INSERT INTO engagements (id, name, org, created_at) "
            "VALUES ('e1', 'Acme', 'acme', '2026-01-01T00:00:00Z')"
        )
        conn.execute(
            """
            INSERT INTO runs (id, engagement_id, mode, playbook, repo, sha, status,
                               scope_json, blast_radius)
            VALUES ('run1', 'e1', 'triage', 'web-app.v1', 'acme/app', 'deadbeef',
                    'running', ?, 'safe')
            """,
            (json.dumps({"repos": [], "hosts": ["app.example"]}),),
        )
    return p


def test_out_of_scope_host_denied(run_db: Path) -> None:
    calls = []

    def execute(args):
        calls.append(args)
        return b"unused"

    with pytest.raises(gateway.OutOfScopeError):
        gateway.invoke(
            "run1", "http_get", {"method": "GET", "url": "https://evil.example/"},
            db_path=run_db, agent="test", execute=execute,
        )
    assert calls == []
    with db.session(run_db) as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM tool_spans").fetchone()["c"]
    assert count == 0


def test_in_scope_safe_get_hashed(run_db: Path) -> None:
    def execute(args):
        return b"ok"

    span = gateway.invoke(
        "run1", "http_get", {"method": "GET", "url": "https://app.example/health"},
        db_path=run_db, agent="test", execute=execute,
    )
    args = {"method": "GET", "url": "https://app.example/health"}
    expected_args_hash = hashlib.sha256(
        json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert span["tool"] == "http_get"
    assert span["args_hash"] == expected_args_hash
    assert span["result_sha256"] == hashlib.sha256(b"ok").hexdigest()
    assert span["run_id"] == "run1"

    with db.session(run_db) as conn:
        row = conn.execute("SELECT * FROM tool_spans WHERE id = ?", (span["id"],)).fetchone()
    assert row is not None
    assert row["tool"] == "http_get"
    assert row["args_hash"] == expected_args_hash
    assert row["result_sha256"] == hashlib.sha256(b"ok").hexdigest()
    assert row["run_id"] == "run1"


def test_safe_denies_post(run_db: Path) -> None:
    calls = []

    def execute(args):
        calls.append(args)
        return b"unused"

    with pytest.raises(gateway.BlastRadiusError):
        gateway.invoke(
            "run1", "http_get",
            {"method": "POST", "url": "https://app.example/submit"},
            db_path=run_db, agent="test", execute=execute,
        )
    assert calls == []
    with db.session(run_db) as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM tool_spans").fetchone()["c"]
    assert count == 0


def test_kill_stops_in_flight_call(run_db: Path) -> None:
    started = threading.Event()
    result: dict = {}

    def execute(args):
        started.set()
        (call_id,) = gateway.in_flight_ids()
        gateway._IN_FLIGHT[call_id].wait(timeout=5)
        return b"too-late"

    def run():
        try:
            gateway.invoke(
                "run1", "http_get", {"method": "GET", "url": "https://app.example/slow"},
                db_path=run_db, agent="test", execute=execute,
            )
        except Exception as e:  # noqa: BLE001
            result["error"] = e

    t = threading.Thread(target=run)
    t.start()
    started.wait(timeout=5)
    (call_id,) = gateway.in_flight_ids()
    gateway.kill(call_id)
    t.join(timeout=5)

    assert isinstance(result.get("error"), gateway.GatewayCancelled)
    with db.session(run_db) as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM tool_spans").fetchone()["c"]
    assert count == 0
