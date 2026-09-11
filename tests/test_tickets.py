"""Accept-time ticketing: dedup, sink selection, and failure containment."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from triage import db, tickets


@pytest.fixture(autouse=True)
def _loopback_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRIAGE_API_TOKEN", raising=False)
    monkeypatch.delenv("TRIAGE_API_HOST", raising=False)
    monkeypatch.delenv("TRIAGE_API_PORT", raising=False)
    monkeypatch.delenv("JIRA_BASE_URL", raising=False)
    monkeypatch.delenv("JIRA_EMAIL", raising=False)
    monkeypatch.delenv("JIRA_API_TOKEN", raising=False)
    monkeypatch.delenv("JIRA_PROJECT", raising=False)


def _client(db_path: Path, *, github=None, jira=None):
    from fastapi.testclient import TestClient

    from api.app import create_app

    db.init_schema(db_path)
    app = create_app(db_path)
    if github is not None:
        app.state.github = github
    if jira is not None:
        app.state.jira = jira
    return TestClient(app)


def _seed_engagement_and_run(
    db_path: Path, run_id: str, engagement_id: str = "e1", policy_json: str = "{}"
) -> None:
    with db.session(db_path) as conn:
        conn.execute(
            "INSERT INTO engagements (id, name, org, policy_json, created_at) "
            "VALUES (?, 'acme-web', 'acme', ?, '2026-09-08T00:00:00+00:00')",
            (engagement_id, policy_json),
        )
        conn.execute(
            "INSERT INTO runs (id, engagement_id, mode, playbook, repo, sha, status, "
            "budget_spent_usd) VALUES (?, ?, 'triage', 'web-app.v1', 'acme/app', "
            "'deadbeef', 'done', 0)",
            (run_id, engagement_id),
        )


def _seed_finding(
    db_path: Path,
    finding_id: str,
    *,
    status: str = "needs_review",
    run_id: str | None = None,
    file: str = "src/a.py",
    line: int = 1,
    rule_id: str = "rule.x",
    repo_url: str = "https://github.com/acme/app.git",
    sha: str = "deadbeefcafebabedeadbeefcafebabe",
    verdict_json: str | None = None,
) -> None:
    with db.session(db_path) as conn:
        conn.execute(
            "INSERT INTO findings (id, repo_url, sha, rule_id, file, line, status, "
            "source_kind, run_id, verdict_json) VALUES (?, ?, ?, ?, ?, ?, ?, "
            "'sast_csv', ?, ?)",
            (finding_id, repo_url, sha, rule_id, file, line, status, run_id, verdict_json),
        )


def _tickets_rows(db_path: Path) -> list:
    with db.session(db_path) as conn:
        return conn.execute("SELECT * FROM tickets").fetchall()


class _FakeGithub:
    def __init__(self):
        self.create_calls = []
        self.comment_calls = []

    def create(self, target, title, body):
        self.create_calls.append((target, title, body))
        return {"external_id": "1", "url": "https://github.com/acme/app/issues/1"}

    def comment(self, target, external_id, body):
        self.comment_calls.append((target, external_id, body))


class _FailingGithub:
    def create(self, target, title, body):
        raise RuntimeError("boom")

    def comment(self, target, external_id, body):
        raise RuntimeError("boom")


class _FakeJira:
    def __init__(self):
        self.create_calls = []
        self.comment_calls = []

    def create(self, target, title, body):
        self.create_calls.append((target, title, body))
        return {"external_id": "JIRA-1", "url": "https://jira.example/browse/JIRA-1"}

    def comment(self, target, external_id, body):
        self.comment_calls.append((target, external_id, body))


def test_accept_creates_one_github_issue(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    github = _FakeGithub()
    client = _client(db_path, github=github)
    _seed_engagement_and_run(db_path, "r1")
    _seed_finding(db_path, "f1", run_id="r1")

    resp = client.post("/findings/f1/review", json={"action": "accept"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "published"
    assert len(body["tickets"]) == 1
    assert body["tickets"][0]["external_id"] == "1"
    assert len(github.create_calls) == 1
    assert len(_tickets_rows(db_path)) == 1


def test_second_publish_comments(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    github = _FakeGithub()
    client = _client(db_path, github=github)
    _seed_engagement_and_run(db_path, "r1")
    _seed_finding(db_path, "f1", run_id="r1")
    _seed_finding(db_path, "f2", run_id="r1")

    r1 = client.post("/findings/f1/review", json={"action": "accept"})
    r2 = client.post("/findings/f2/review", json={"action": "accept"})

    assert r1.status_code == 200 and r2.status_code == 200
    assert len(github.create_calls) == 1
    assert len(github.comment_calls) == 1
    assert r1.json()["tickets"][0]["external_id"] == r2.json()["tickets"][0]["external_id"]
    assert len(_tickets_rows(db_path)) == 2


def test_jira_sink_when_policy_says_jira(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    github = _FakeGithub()
    jira = _FakeJira()
    client = _client(db_path, github=github, jira=jira)
    _seed_engagement_and_run(
        db_path, "r1", policy_json='{"ticket_sink": "jira", "jira_project": "SEC"}'
    )
    _seed_finding(db_path, "f1", run_id="r1")

    resp = client.post("/findings/f1/review", json={"action": "accept"})

    assert resp.status_code == 200
    assert resp.json()["tickets"][0]["sink"] == "jira"
    assert len(jira.create_calls) == 1
    assert jira.create_calls[0][0] == "SEC"
    assert len(github.create_calls) == 0


def test_sink_failure_still_publishes(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    client = _client(db_path, github=_FailingGithub())
    _seed_engagement_and_run(db_path, "r1")
    _seed_finding(db_path, "f1", run_id="r1")

    resp = client.post("/findings/f1/review", json={"action": "accept"})

    assert resp.status_code == 200
    assert resp.json()["status"] == "published"
    assert resp.json()["tickets"] == []
    assert _tickets_rows(db_path) == []


def test_reject_does_not_ticket(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    github = _FakeGithub()
    client = _client(db_path, github=github)
    _seed_engagement_and_run(db_path, "r1")
    _seed_finding(db_path, "f1", run_id="r1")

    resp = client.post("/findings/f1/review", json={"action": "reject"})

    assert resp.status_code == 200
    assert resp.json()["status"] == "done"
    assert "tickets" not in resp.json()
    assert len(github.create_calls) == 0


def test_get_finding_detail_includes_tickets(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    client = _client(db_path, github=_FakeGithub())
    _seed_engagement_and_run(db_path, "r1")
    _seed_finding(db_path, "f1", run_id="r1")
    client.post("/findings/f1/review", json={"action": "accept"})

    detail = client.get("/findings/f1")
    assert detail.status_code == 200
    assert len(detail.json()["tickets"]) == 1

    listing = client.get("/findings")
    assert listing.status_code == 200
    assert "tickets" not in listing.json()["findings"][0]


def test_accept_with_no_injected_sink_omits_tickets_key(tmp_path: Path) -> None:
    """Documents the app.state gate: no `github`/`jira` on `app.state` means the
    ticketing hook is never invoked, so no default sink ever shells out during
    a plain accept. Mirrors `tests/test_api.py::test_review_accept_publishes`,
    which this must not break."""
    db_path = tmp_path / "api.db"
    client = _client(db_path)
    _seed_engagement_and_run(db_path, "r1")
    _seed_finding(db_path, "f1", run_id="r1")

    resp = client.post("/findings/f1/review", json={"action": "accept"})

    assert resp.status_code == 200
    assert resp.json() == {"id": "f1", "status": "published"}
    assert _tickets_rows(db_path) == []


def test_ticket_body_reads_proof_from_the_consolidated_envelope(tmp_path: Path) -> None:
    """`verdict_json` is always `{pass1, pass2, consolidated}`; `proof` lives on
    `consolidated`, never at the top level. A ticket for a real http_replay
    verdict must report that proof kind, its replay command and artifact hash,
    and the verifier's real pass/fail — not silently fall back to `harness`."""
    db_path = tmp_path / "api.db"
    github = _FakeGithub()
    client = _client(db_path, github=github)
    _seed_engagement_and_run(db_path, "r1")
    verdict_json = json.dumps(
        {
            "pass1": {},
            "pass2": {},
            "consolidated": {
                "proof": {
                    "kind": "http_replay",
                    "artifact_uri": "artifacts/f1.har",
                    "artifact_sha256": "deadbeef" * 8,
                    "replay": {"command": "curl -s https://target/v1", "passed": True},
                }
            },
        }
    )
    _seed_finding(db_path, "f1", run_id="r1", verdict_json=verdict_json)
    with db.session(db_path) as conn:
        conn.execute(
            "UPDATE findings SET verifier_json = ? WHERE id = 'f1'",
            (json.dumps({"schema_ok": True, "replay": {"passed": True}}),),
        )

    resp = client.post("/findings/f1/review", json={"action": "accept"})

    assert resp.status_code == 200
    target, title, body = github.create_calls[0]
    assert "proof.kind: http_replay" in body
    assert "replay: curl -s https://target/v1" in body
    assert "verifier passed: True" in body
    assert f"artifact_sha256: {'deadbeef' * 8}" in body
    assert tickets.proof_kind_of(verdict_json) == "http_replay"


def test_illegal_accept_does_not_ticket(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    github = _FakeGithub()
    client = _client(db_path, github=github)
    _seed_engagement_and_run(db_path, "r1")
    _seed_finding(db_path, "f1", run_id="r1", status="done")

    resp = client.post("/findings/f1/review", json={"action": "accept"})

    assert resp.status_code == 409
    assert len(github.create_calls) == 0
    assert _tickets_rows(db_path) == []


def test_concurrent_accept_of_dedup_matching_finding_does_not_double_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """While f1's create() is still in flight, a second accept of a
    dedup-matching finding f2 must see f1's in-progress claim and back off
    instead of creating a second GitHub issue for the same bug.

    Simulated by nesting a second `tickets.publish()` call inside the first
    sink's own `create()` — a deterministic single-thread stand-in for two
    requests racing on the same dedup key (same technique family as
    review-cas.md's monkeypatched lost-race test: no real threads)."""
    monkeypatch.setattr(tickets, "_CLAIM_MAX_WAIT_S", 0.2)
    monkeypatch.setattr(tickets, "_CLAIM_POLL_INTERVAL_S", 0.02)
    db_path = tmp_path / "api.db"
    create_calls = []
    nested_result = {}

    class RacingGithub:
        def create(self, target, title, body):
            create_calls.append((target, title, body))
            with db.session(db_path) as inner_conn:
                nested_result["value"] = tickets.publish(
                    inner_conn, "f2", github=self
                )
            return {"external_id": "1", "url": "https://github.com/acme/app/issues/1"}

        def comment(self, target, external_id, body):
            raise AssertionError("comment should not be reached in this test")

    db.init_schema(db_path)
    _seed_finding(db_path, "f1")
    _seed_finding(db_path, "f2")

    with db.session(db_path) as conn:
        result = tickets.publish(conn, "f1", github=RacingGithub())

    assert len(create_calls) == 1
    assert nested_result["value"] == []
    assert result[0]["external_id"] == "1"
    with db.session(db_path) as conn:
        rows = conn.execute("SELECT finding_id, external_id FROM tickets").fetchall()
    assert [(r["finding_id"], r["external_id"]) for r in rows] == [("f1", "1")]


def test_true_concurrent_threads_serialize_on_the_dedup_claim(tmp_path: Path) -> None:
    """Real `threading.Thread`s, each with its own `sqlite3.Connection` to the
    same file — not the single-thread nested-call stand-in above — must still
    serialize to exactly one `create()` + one `comment()` for two findings
    sharing a dedup key. Proves `BEGIN IMMEDIATE` actually blocks a second
    connection rather than merely looking like it does in a sequential test."""
    db_path = tmp_path / "api.db"
    db.init_schema(db_path)
    _seed_finding(db_path, "f1")
    _seed_finding(db_path, "f2")

    barrier = threading.Barrier(2)
    call_lock = threading.Lock()
    create_calls = []
    comment_calls = []

    class ThreadsafeGithub:
        def create(self, target, title, body):
            with call_lock:
                create_calls.append((target, title, body))
            return {"external_id": "1", "url": "https://github.com/acme/app/issues/1"}

        def comment(self, target, external_id, body):
            with call_lock:
                comment_calls.append((target, external_id, body))

    results: dict[str, list] = {}

    def run(finding_id: str) -> None:
        barrier.wait(timeout=5)
        with db.session(db_path) as conn:
            results[finding_id] = tickets.publish(conn, finding_id, github=ThreadsafeGithub())

    threads = [threading.Thread(target=run, args=(fid,)) for fid in ("f1", "f2")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(create_calls) == 1
    assert len(comment_calls) == 1
    assert results["f1"][0]["external_id"] == "1"
    assert results["f2"][0]["external_id"] == "1"
    with db.session(db_path) as conn:
        rows = conn.execute("SELECT finding_id, external_id FROM tickets").fetchall()
    assert {(r["finding_id"], r["external_id"]) for r in rows} == {("f1", "1"), ("f2", "1")}


def test_stale_placeholder_is_reclaimed_not_blocked_forever(tmp_path: Path) -> None:
    """An abandoned claim (its process died mid-create, e.g. killed during a
    deploy) must not permanently block every future accept of the same bug —
    it should be reclaimed once older than `_CLAIM_STALE_AFTER_S`."""
    db_path = tmp_path / "api.db"
    db.init_schema(db_path)
    _seed_finding(db_path, "f1")
    _seed_finding(db_path, "f2")

    stale_at = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    with db.session(db_path) as conn:
        conn.execute(
            "INSERT INTO tickets (id, finding_id, sink, external_id, url, published_at) "
            "VALUES ('orphan', 'f1', 'github', NULL, NULL, ?)",
            (stale_at,),
        )

    github = _FakeGithub()
    with db.session(db_path) as conn:
        result = tickets.publish(conn, "f2", github=github)

    assert len(github.create_calls) == 1
    assert result[0]["external_id"] == "1"
    with db.session(db_path) as conn:
        rows = conn.execute(
            "SELECT finding_id, external_id FROM tickets ORDER BY finding_id"
        ).fetchall()
    # f1's orphaned placeholder is gone; f2 claimed the key and resolved it.
    assert [(r["finding_id"], r["external_id"]) for r in rows] == [("f2", "1")]


def test_ticketing_pipeline_failure_still_publishes_instead_of_500(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bug or DB error inside the ticketing pipeline itself — not a caught
    sink.create/comment failure — must not turn an already-successful accept
    (the CAS write already committed) into a 500. It degrades to tickets: []
    like any other sink failure."""
    db_path = tmp_path / "api.db"
    client = _client(db_path, github=_FakeGithub())
    _seed_engagement_and_run(db_path, "r1")
    _seed_finding(db_path, "f1", run_id="r1")

    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(tickets, "_find_candidate", _boom)

    resp = client.post("/findings/f1/review", json={"action": "accept"})

    assert resp.status_code == 200
    assert resp.json()["status"] == "published"
    assert resp.json()["tickets"] == []
    assert _status_of(db_path, "f1") == "published"


def _status_of(db_path: Path, finding_id: str) -> str:
    with db.session(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
    return row["status"]
