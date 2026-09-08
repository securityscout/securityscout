"""Control-plane HTTP: engagement, run, findings list, replay enqueue."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from triage import db
from triage.config import REPO_ROOT


@pytest.fixture(autouse=True)
def _loopback_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pytest must never need an exported token or a bound address."""
    monkeypatch.delenv("TRIAGE_API_TOKEN", raising=False)
    monkeypatch.delenv("TRIAGE_API_HOST", raising=False)
    monkeypatch.delenv("TRIAGE_API_PORT", raising=False)


def _client(db_path: Path):
    from fastapi.testclient import TestClient

    from api.app import create_app

    db.init_schema(db_path)
    return TestClient(create_app(db_path))


def _seed_finding(db_path: Path, finding_id: str, status: str) -> None:
    with db.session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO findings (
              id, repo_url, sha, rule_id, file, line, status, source_kind
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'sast_csv')
            """,
            (
                finding_id,
                "https://github.com/acme/app.git",
                "deadbeefcafebabedeadbeefcafebabe",
                "rule.x",
                "src/a.py",
                1,
                status,
            ),
        )


def _status_of(db_path: Path, finding_id: str) -> str:
    with db.session(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
    return row["status"]


def test_create_engagement_create_run_list_findings_replay_202(
    tmp_path: Path,
) -> None:
    from fastapi.testclient import TestClient

    from api.app import create_app

    db_path = tmp_path / "api.db"
    db.init_schema(db_path)
    client = TestClient(create_app(db_path))

    created = client.post(
        "/engagements",
        json={"name": "acme-web", "org": "acme", "policy_json": {}},
    )
    assert created.status_code == 201
    engagement = created.json()
    assert engagement["name"] == "acme-web"
    assert engagement["org"] == "acme"
    eng_id = engagement["id"]

    run_resp = client.post(
        f"/engagements/{eng_id}/runs",
        json={
            "mode": "triage",
            "playbook": "web-app.v1",
            "repo": "acme/app",
            "sha": "deadbeefcafebabedeadbeefcafebabe",
        },
    )
    assert run_resp.status_code == 201
    run = run_resp.json()
    assert run["engagement_id"] == eng_id
    assert run["mode"] == "triage"
    assert run["status"] == "queued"
    run_id = run["id"]

    with db.session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO findings (
              id, repo_url, sha, rule_id, file, line, status, run_id, source_kind
            ) VALUES (?, ?, ?, ?, ?, ?, 'done', ?, 'sast_csv')
            """,
            (
                "f1",
                "https://github.com/acme/app.git",
                "deadbeefcafebabedeadbeefcafebabe",
                "rule.x",
                "src/a.py",
                1,
                run_id,
            ),
        )

    listed = client.get("/findings", params={"engagement_id": eng_id})
    assert listed.status_code == 200
    findings = listed.json()["findings"]
    assert len(findings) == 1
    assert findings[0]["id"] == "f1"
    assert findings[0]["run_id"] == run_id

    replay = client.post("/findings/f1/replay")
    assert replay.status_code == 202
    body = replay.json()
    assert body["finding_id"] == "f1"
    assert body["replay_status"] == "queued"
    assert "passed" not in body


def test_token_set_requires_bearer_on_routers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRIAGE_API_TOKEN", "s3cret")
    client = _client(tmp_path / "api.db")
    payload = {"name": "acme-web", "org": "acme", "policy_json": {}}

    unauthenticated = client.post("/engagements", json=payload)
    assert unauthenticated.status_code == 401
    assert unauthenticated.json() == {
        "error": "unauthorized",
        "detail": "invalid or missing token",
    }

    wrong = client.post(
        "/engagements", json=payload, headers={"Authorization": "Bearer nope"}
    )
    assert wrong.status_code == 401
    assert wrong.json()["error"] == "unauthorized"

    good = client.post(
        "/engagements", json=payload, headers={"Authorization": "Bearer s3cret"}
    )
    assert good.status_code == 201
    assert good.json()["name"] == "acme-web"


def test_health_open_when_token_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRIAGE_API_TOKEN", "s3cret")
    client = _client(tmp_path / "api.db")

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"ok": True}


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_check_bind_allows_loopback_without_token(host: str) -> None:
    from api.__main__ import check_bind

    check_bind(host, None)
    check_bind(host, "")


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "*", "10.0.0.4", "api.internal"])
def test_check_bind_refuses_non_loopback_without_token(host: str) -> None:
    from api.__main__ import check_bind

    for token in (None, ""):
        with pytest.raises(RuntimeError) as raised:
            check_bind(host, token)
        message = str(raised.value)
        assert "TRIAGE_API_TOKEN" in message
        assert host in message


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "0.0.0.0", "10.0.0.4"])
def test_check_bind_allows_any_host_with_token(host: str) -> None:
    from api.__main__ import check_bind

    check_bind(host, "s3cret")


def test_module_main_refuses_non_loopback_without_token() -> None:
    # Blank, not absent: python-dotenv skips keys already in the environment,
    # so this also stops a developer's .env token from making the child bind.
    env = dict(os.environ, TRIAGE_API_TOKEN="", TRIAGE_API_HOST="0.0.0.0")

    proc = subprocess.run(
        [sys.executable, "-m", "api"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=3,
    )

    assert proc.returncode != 0
    output = proc.stdout + proc.stderr
    assert "TRIAGE_API_TOKEN" in output
    assert "0.0.0.0" in output
    assert "ImportError" not in output
    assert "Address already in use" not in output


def test_review_accept_publishes(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    client = _client(db_path)
    _seed_finding(db_path, "f1", "needs_review")

    resp = client.post("/findings/f1/review", json={"action": "accept"})

    assert resp.status_code == 200
    assert resp.json() == {"id": "f1", "status": "published"}
    assert _status_of(db_path, "f1") == "published"


@pytest.mark.parametrize("action", ["reject", "accept_risk"])
def test_review_reject_and_accept_risk_close(tmp_path: Path, action: str) -> None:
    db_path = tmp_path / "api.db"
    client = _client(db_path)
    _seed_finding(db_path, "f1", "needs_review")

    resp = client.post("/findings/f1/review", json={"action": action})

    assert resp.status_code == 200
    assert resp.json() == {"id": "f1", "status": "done"}
    assert _status_of(db_path, "f1") == "done"


def test_review_illegal_transition_leaves_row(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    client = _client(db_path)
    _seed_finding(db_path, "f1", "done")

    resp = client.post("/findings/f1/review", json={"action": "accept"})

    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "illegal_transition"
    assert "done" in body["detail"]
    assert "published" in body["detail"]
    assert _status_of(db_path, "f1") == "done"


def test_review_unknown_action_400(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    client = _client(db_path)
    _seed_finding(db_path, "f1", "needs_review")

    resp = client.post("/findings/f1/review", json={"action": "burn"})

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert _status_of(db_path, "f1") == "needs_review"


def test_review_missing_finding_404(tmp_path: Path) -> None:
    client = _client(tmp_path / "api.db")

    resp = client.post("/findings/nope/review", json={"action": "accept"})

    assert resp.status_code == 404
    assert resp.json()["error"] == "not_found"


def test_review_lost_race_returns_409_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Someone else moves the row between the handler's SELECT and its write.

    Autocommit commits the flip immediately, so the handler's own
    `row["status"]` is stale by the time it reaches the write.
    """
    from api import routes_findings

    db_path = tmp_path / "api.db"
    client = _client(db_path)
    _seed_finding(db_path, "f1", "needs_review")

    real_get_finding = routes_findings._get_finding

    def racing_get_finding(conn, finding_id):
        row = real_get_finding(conn, finding_id)
        conn.execute("UPDATE findings SET status = 'done' WHERE id = ?", (finding_id,))
        return row

    monkeypatch.setattr(routes_findings, "_get_finding", racing_get_finding)

    resp = client.post("/findings/f1/review", json={"action": "accept"})

    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "conflict"
    assert "f1" in body["detail"]
    assert "needs_review" in body["detail"]
    assert _status_of(db_path, "f1") == "done"


def test_review_route_writes_through_cas_status() -> None:
    import inspect

    from api import routes_findings

    source = inspect.getsource(routes_findings.review_finding)

    assert "cas_status(" in source
    assert "apply_transition" not in source
    assert "UPDATE findings" not in source
