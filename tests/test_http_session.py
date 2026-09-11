"""Acceptance tests for triage/http_session.py."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from triage import db, gateway, http_session


@pytest.fixture(autouse=True)
def _close_sessions():
    yield
    for run_id in list(http_session._SESSIONS):
        http_session.close_session(run_id)


def test_capture_http_returns_transcript_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    http_session.get_session("run-shape", transport=httpx.MockTransport(handler))
    transcript = http_session.capture_http("run-shape", "GET", "https://app.example/health")

    assert transcript["request"] == {"method": "GET", "url": "https://app.example/health"}
    assert transcript["response"]["status"] == 200
    assert json.loads(transcript["response"]["body_excerpt"]) == {"ok": True}
    assert isinstance(transcript["response"]["headers"], dict)
    assert isinstance(transcript["timing_ms"], int)


def test_body_excerpt_is_capped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="x" * 5000)

    http_session.get_session("run-cap", transport=httpx.MockTransport(handler))
    transcript = http_session.capture_http("run-cap", "GET", "https://app.example/big")
    assert len(transcript["response"]["body_excerpt"]) == 2000


def test_session_persists_cookies_within_run() -> None:
    seen_cookies = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookies.append(request.headers.get("cookie"))
        if len(seen_cookies) == 1:
            return httpx.Response(200, headers={"set-cookie": "sid=abc123; Path=/"})
        return httpx.Response(200)

    http_session.get_session("run-cookie", transport=httpx.MockTransport(handler))
    http_session.capture_http("run-cookie", "GET", "https://app.example/login")
    http_session.capture_http("run-cookie", "GET", "https://app.example/account")

    assert seen_cookies[0] is None
    assert seen_cookies[1] is not None
    assert "sid=abc123" in seen_cookies[1]


def test_fresh_run_id_does_not_share_cookies() -> None:
    def handler_a(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"set-cookie": "sid=abc123; Path=/"})

    seen = []

    def handler_b(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("cookie"))
        return httpx.Response(200)

    http_session.get_session("run-a", transport=httpx.MockTransport(handler_a))
    http_session.capture_http("run-a", "GET", "https://app.example/login")

    http_session.get_session("run-b", transport=httpx.MockTransport(handler_b))
    http_session.capture_http("run-b", "GET", "https://app.example/account")

    assert seen == [None]


def test_get_session_ignores_transport_on_second_call() -> None:
    client1 = http_session.get_session("run-cache", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    client2 = http_session.get_session("run-cache", transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    assert client1 is client2


def test_close_session_is_idempotent() -> None:
    http_session.get_session("run-close", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    http_session.close_session("run-close")
    http_session.close_session("run-close")  # no error


@pytest.fixture()
def run_db(tmp_path: Path) -> Path:
    p = tmp_path / "http-session-test.db"
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
            VALUES ('run-gw', 'e1', 'hunt', 'web-app.v1', 'acme/app', 'deadbeef',
                    'running', ?, 'safe')
            """,
            (json.dumps({"repos": [], "hosts": ["app.example"]}),),
        )
    return p


def test_gateway_execute_writes_artifact_matching_span_hash(run_db: Path, tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    http_session.get_session("run-gw", transport=httpx.MockTransport(handler))
    transcripts_dir = tmp_path / "transcripts"

    span = gateway.invoke(
        "run-gw", "http_get", {"method": "GET", "url": "https://app.example/health"},
        db_path=run_db, agent="hunter",
        execute=http_session.gateway_execute("run-gw", transcripts_dir),
    )

    artifact_path = transcripts_dir / f"{span['result_sha256']}.json"
    assert artifact_path.is_file()
    assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() == span["result_sha256"]

    body = json.loads(artifact_path.read_bytes())
    assert body["request"] == {"method": "GET", "url": "https://app.example/health"}
