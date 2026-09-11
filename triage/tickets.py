"""Ticket sinks: GitHub Issues + Jira, dedup by (repo, sha, class, location, proof kind).

`publish` is the accept-time side effect (called from the API process, never
a worker). Both sinks are injectable so tests never touch the network; the
default GitHub runner shells out to `gh api` (same stdin-closed pattern as
`github_org._gh_run`), the default Jira runner is a plain `httpx` call with
HTTP Basic auth. `DefaultGithubSink`/`DefaultJiraSink` are wired onto
`app.state` only by `api/__main__.py`'s `main()` — the one process path
`TestClient(create_app(...))` never runs — so a plain `pytest` run never
shells out for real.

Concurrent accepts of two different findings that hash to the same dedup
key must not both decide "no match, create" — `_claim_or_find_match` closes
that race with a short `BEGIN IMMEDIATE` critical section around the
candidate check plus a claim-placeholder insert (external_id/url left NULL,
already-nullable columns), so only one accept ever calls `sink.create` per
key; a second racer polls the placeholder up to `_CLAIM_MAX_WAIT_S`. A
placeholder older than `_CLAIM_STALE_AFTER_S` is treated as abandoned (the
claimant's process died mid-`create()`, e.g. killed during a deploy) and is
reclaimed rather than blocking that dedup key forever.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Protocol

# Bounds the wait for a concurrent accept's in-flight create (see
# `_claim_or_find_match`). Module-level so tests can shrink them.
_CLAIM_MAX_WAIT_S = 5.0
_CLAIM_POLL_INTERVAL_S = 0.05
# A placeholder older than this is treated as abandoned (its claimant's
# process died before resolving it) and is reclaimed rather than left to
# block this dedup key forever.
_CLAIM_STALE_AFTER_S = 30.0


class TicketSink(Protocol):
    def create(self, target: str, title: str, body: str) -> dict[str, str]: ...

    def comment(self, target: str, external_id: str, body: str) -> None: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalized_location(file: str, line: int) -> str:
    return f"{str(file).strip().lower()}:{line}"


def vuln_class_of(rule_id: str) -> str:
    prefix = "hunt."
    if rule_id.startswith(prefix):
        return rule_id[len(prefix) :]
    return rule_id


def _parse_json(text: str | None) -> dict[str, Any]:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _consolidated_of(verdict_json: str | None) -> dict[str, Any]:
    """Unwrap the `{pass1, pass2, consolidated}` envelope `verdict_json` holds.

    `triage_worker.py` and `verifier.py` always nest the semantic verdict
    (the object `data/verdict.schema.json` validates, with `proof` on it)
    under `consolidated`; a top-level `proof` key never exists on the raw
    column. Falls back to the parsed dict itself for a flat test fixture
    that skips the envelope.
    """
    parsed = _parse_json(verdict_json)
    consolidated = parsed.get("consolidated")
    return consolidated if isinstance(consolidated, dict) else parsed


def proof_kind_of(verdict_json: str | None) -> str:
    proof = _consolidated_of(verdict_json).get("proof")
    if isinstance(proof, dict) and isinstance(proof.get("kind"), str):
        return proof["kind"]
    return "harness"


def dedup_key(
    repo: str, sha: str, vuln_class: str, normalized_location_: str, proof_kind: str
) -> str:
    payload = f"{repo}|{sha}|{vuln_class}|{normalized_location_}|{proof_kind}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _finding_dedup_key(row: Any) -> str:
    return dedup_key(
        row["repo_url"],
        row["sha"],
        vuln_class_of(row["rule_id"]),
        normalized_location(row["file"], row["line"]),
        proof_kind_of(row["verdict_json"]),
    )


def _owner_repo(repo_url: str) -> str:
    text = repo_url.strip()
    for prefix in ("https://", "http://"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    if text.startswith("git@") and ":" in text:
        # git@github.com:acme/app.git
        text = text.split(":", 1)[1]
    if text.endswith(".git"):
        text = text[: -len(".git")]
    parts = [p for p in text.split("/") if p]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return text


def _resolve_sink(conn: Any, run_id: str | None) -> tuple[str, dict[str, Any]]:
    if not run_id:
        return "github", {}
    run = conn.execute(
        "SELECT engagement_id FROM runs WHERE id = ?", (run_id,)
    ).fetchone()
    if run is None:
        return "github", {}
    eng = conn.execute(
        "SELECT policy_json FROM engagements WHERE id = ?", (run["engagement_id"],)
    ).fetchone()
    if eng is None:
        return "github", {}
    policy = _parse_json(eng["policy_json"])
    sink = policy.get("ticket_sink")
    if sink not in ("github", "jira"):
        sink = "github"
    return sink, policy


def _verifier_passed(verifier_json: dict[str, Any]) -> bool | None:
    """`verifier.py` writes `{"replay": {"passed": bool, ...}, ...}` — the
    flag is never a top-level key of `verifier_json`."""
    replay = verifier_json.get("replay")
    if isinstance(replay, dict) and "passed" in replay:
        return replay["passed"]
    return None


def _ticket_body(row: Any, consolidated: dict[str, Any], verifier: dict[str, Any]) -> str:
    proof = consolidated.get("proof") if isinstance(consolidated.get("proof"), dict) else {}
    replay = proof.get("replay") if isinstance(proof.get("replay"), dict) else {}
    lines = [
        f"finding: {row['id']}",
        f"repo: {row['repo_url']}",
        f"sha: {row['sha']}",
        f"rule: {row['rule_id']}",
        f"location: {row['file']}:{row['line']}",
        f"proof.kind: {proof.get('kind', 'harness')}",
    ]
    if replay.get("command"):
        lines.append(f"replay: {replay['command']}")
    passed = _verifier_passed(verifier) if isinstance(verifier, dict) else None
    if passed is not None:
        lines.append(f"verifier passed: {passed}")
    if proof.get("artifact_sha256"):
        lines.append(f"artifact_sha256: {proof['artifact_sha256']}")
    return "\n".join(lines)


def list_for_finding(conn: Any, finding_id: str) -> list[dict[str, Any]]:
    # external_id IS NOT NULL excludes an in-flight or orphaned claim
    # placeholder (see `_claim_or_find_match`) — never expose one over HTTP.
    rows = conn.execute(
        "SELECT id, sink, external_id, url, published_at FROM tickets "
        "WHERE finding_id = ? AND external_id IS NOT NULL ORDER BY published_at",
        (finding_id,),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "sink": r["sink"],
            "external_id": r["external_id"],
            "url": r["url"],
            "published_at": r["published_at"],
        }
        for r in rows
    ]


def _insert(
    conn: Any, finding_id: str, sink: str, external_id: str, url: str
) -> None:
    conn.execute(
        "INSERT INTO tickets (id, finding_id, sink, external_id, url, published_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (uuid.uuid4().hex, finding_id, sink, external_id, url, _now()),
    )


def _insert_placeholder(conn: Any, finding_id: str, sink: str) -> None:
    """Reserve the dedup key for `finding_id` before the sink `create()` call.

    `external_id`/`url` are nullable on `tickets` already — no schema change.
    This row doubles as `finding_id`'s own ticket row once resolved, so no
    second INSERT happens on the create path.
    """
    conn.execute(
        "INSERT INTO tickets (id, finding_id, sink, external_id, url, published_at) "
        "VALUES (?, ?, ?, NULL, NULL, ?)",
        (uuid.uuid4().hex, finding_id, sink, _now()),
    )


def _resolve_placeholder(
    conn: Any, finding_id: str, external_id: str, url: str
) -> None:
    conn.execute(
        "UPDATE tickets SET external_id = ?, url = ? "
        "WHERE finding_id = ? AND external_id IS NULL",
        (external_id, url, finding_id),
    )


def _delete_placeholder(conn: Any, finding_id: str) -> None:
    conn.execute(
        "DELETE FROM tickets WHERE finding_id = ? AND external_id IS NULL",
        (finding_id,),
    )


def _dedup_key_for_candidate(row: Any, candidate: Any) -> str:
    return dedup_key(
        row["repo_url"],
        row["sha"],
        vuln_class_of(candidate["rule_id"]),
        normalized_location(candidate["file"], candidate["line"]),
        proof_kind_of(candidate["verdict_json"]),
    )


def _find_candidate(conn: Any, row: Any, key: str) -> Any:
    candidates = conn.execute(
        "SELECT t.finding_id, t.sink, t.external_id, t.url, t.published_at, "
        "f.rule_id, f.file, f.line, f.verdict_json "
        "FROM tickets t JOIN findings f ON f.id = t.finding_id "
        "WHERE f.repo_url = ? AND f.sha = ?",
        (row["repo_url"], row["sha"]),
    ).fetchall()
    return next((c for c in candidates if _dedup_key_for_candidate(row, c) == key), None)


def _placeholder_age_s(published_at: str) -> float:
    claimed = datetime.fromisoformat(published_at)
    return (datetime.now(timezone.utc) - claimed).total_seconds()


def _claim_or_find_match(
    conn: Any, row: Any, key: str, sink_name: str
) -> tuple[str, Any]:
    """Atomically decide: comment on an existing ticket, or claim the key.

    Two concurrent accepts of dedup-matching findings must not both decide
    "no match, I'll create" — that produces two GitHub issues for one bug.
    A short `BEGIN IMMEDIATE` critical section (SQLite's write lock; `db.
    connect` already sets a 5s busy_timeout) makes "check candidates, then
    either read a resolved match or claim the key" atomic across
    connections. The external sink call happens outside the lock so a slow
    `gh`/Jira request never blocks unrelated writes. A second accept that
    lands mid-window instead finds the claimant's placeholder row
    (`external_id IS NULL`) and polls it, bounded by `_CLAIM_MAX_WAIT_S` —
    unless that placeholder is already older than `_CLAIM_STALE_AFTER_S`,
    meaning its claimant's process died before resolving it; that claim is
    reclaimed immediately instead of waited out, so one lost process can't
    permanently block every future accept of a bug with the same dedup key.

    Returns `("existing", ticket_row)`, `("claimed", None)` — caller now
    owns `finding_id`'s placeholder row and must create — or
    `("timeout", None)` if a (still-live) racing claim never resolved in
    time.
    """
    deadline = time.monotonic() + _CLAIM_MAX_WAIT_S
    while True:
        conn.execute("BEGIN IMMEDIATE")
        try:
            match = _find_candidate(conn, row, key)
            if match is None:
                _insert_placeholder(conn, row["id"], sink_name)
                conn.execute("COMMIT")
                return "claimed", None
            if match["external_id"] is not None:
                conn.execute("COMMIT")
                return "existing", match
            if _placeholder_age_s(match["published_at"]) >= _CLAIM_STALE_AFTER_S:
                _delete_placeholder(conn, match["finding_id"])
                _insert_placeholder(conn, row["id"], sink_name)
                conn.execute("COMMIT")
                return "claimed", None
            conn.execute("COMMIT")  # match is a live pending placeholder; wait it out
        except Exception:
            conn.execute("ROLLBACK")
            raise
        if time.monotonic() >= deadline:
            return "timeout", None
        time.sleep(_CLAIM_POLL_INTERVAL_S)


def _gh_run(argv: list[str], *, timeout: float = 60.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv, capture_output=True, encoding="latin-1",
            stdin=subprocess.DEVNULL, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return -1, "", f"{type(exc).__name__}: {exc}"
    return proc.returncode, proc.stdout, proc.stderr


class DefaultGithubSink:
    """`gh api` against `repos/<owner>/<name>/issues[/<n>/comments]`."""

    def create(self, target: str, title: str, body: str) -> dict[str, str]:
        rc, out, err = _gh_run(
            [
                "gh", "api", f"repos/{target}/issues",
                "-f", f"title={title}", "-f", f"body={body}",
            ]
        )
        if rc != 0:
            raise RuntimeError(
                f"gh api repos/{target}/issues -> rc={rc}: {(err or out).strip()[:200]}"
            )
        data = json.loads(out)
        return {"external_id": str(data["number"]), "url": data["html_url"]}

    def comment(self, target: str, external_id: str, body: str) -> None:
        rc, out, err = _gh_run(
            [
                "gh", "api", f"repos/{target}/issues/{external_id}/comments",
                "-f", f"body={body}",
            ]
        )
        if rc != 0:
            raise RuntimeError(
                f"gh api repos/{target}/issues/{external_id}/comments -> "
                f"rc={rc}: {(err or out).strip()[:200]}"
            )


class DefaultJiraSink:
    """`httpx` POST to `{JIRA_BASE_URL}/rest/api/3/issue[/{key}/comment]`."""

    def _auth(self) -> tuple[str, str, str]:
        base = os.environ.get("JIRA_BASE_URL")
        email = os.environ.get("JIRA_EMAIL")
        token = os.environ.get("JIRA_API_TOKEN")
        if not base or not email or not token:
            raise RuntimeError(
                "JIRA_BASE_URL, JIRA_EMAIL and JIRA_API_TOKEN must all be set"
            )
        return base, email, token

    def create(self, target: str, title: str, body: str) -> dict[str, str]:
        import httpx

        base, email, token = self._auth()
        resp = httpx.post(
            f"{base}/rest/api/3/issue",
            auth=(email, token),
            json={
                "fields": {
                    "project": {"key": target},
                    "summary": title,
                    "description": body,
                    "issuetype": {"name": "Bug"},
                }
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return {"external_id": data["key"], "url": f"{base}/browse/{data['key']}"}

    def comment(self, target: str, external_id: str, body: str) -> None:
        import httpx

        base, email, token = self._auth()
        resp = httpx.post(
            f"{base}/rest/api/3/issue/{external_id}/comment",
            auth=(email, token),
            json={"body": body},
        )
        resp.raise_for_status()


def publish(
    conn: Any,
    finding_id: str,
    *,
    github: TicketSink | None = None,
    jira: TicketSink | None = None,
) -> list[dict[str, Any]]:
    row = conn.execute(
        "SELECT id, repo_url, sha, rule_id, file, line, run_id, "
        "verdict_json, verifier_json FROM findings WHERE id = ?",
        (finding_id,),
    ).fetchone()
    if row is None:
        return []

    github = github or DefaultGithubSink()
    jira = jira or DefaultJiraSink()

    key = _finding_dedup_key(row)
    sink_name, policy = _resolve_sink(conn, row["run_id"])
    consolidated = _consolidated_of(row["verdict_json"])
    verifier = _parse_json(row["verifier_json"])
    title = f"[{row['rule_id']}] {row['file']}:{row['line']}"
    body = _ticket_body(row, consolidated, verifier)

    def _target(sink_of: str) -> str:
        if sink_of == "jira":
            return policy.get("jira_project") or os.environ.get("JIRA_PROJECT") or ""
        return _owner_repo(row["repo_url"])

    outcome, match = _claim_or_find_match(conn, row, key, sink_name)

    if outcome == "timeout":
        return []

    if outcome == "existing":
        sink = jira if match["sink"] == "jira" else github
        try:
            sink.comment(_target(match["sink"]), match["external_id"], body)
        except Exception:
            return list_for_finding(conn, finding_id)
        _insert(conn, finding_id, match["sink"], match["external_id"], match["url"])
        return list_for_finding(conn, finding_id)

    # outcome == "claimed": finding_id already has a placeholder row reserving
    # this dedup key (inserted by _claim_or_find_match); resolve or release it.
    sink = jira if sink_name == "jira" else github
    try:
        created = sink.create(_target(sink_name), title, body)
    except Exception:
        _delete_placeholder(conn, finding_id)
        return []

    _resolve_placeholder(conn, finding_id, created["external_id"], created["url"])
    return list_for_finding(conn, finding_id)
