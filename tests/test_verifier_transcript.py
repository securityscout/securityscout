"""Acceptance tests for the transcript-kind branch of triage/verifier.py.

http_replay / browser_trace proofs are self-contained transcripts: the
verifier hash-checks the artifact on disk and never touches the network
or a git worktree. `artifact_uri` is hunter-authored and untrusted, so
these tests also cover the tool_spans provenance gate: a declared
`artifact_sha256` must already be a hash this run's own gateway-mediated
capture produced before the file is even opened.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from triage import db, verifier


def _write_artifact(tmp_path: Path, transcript: dict) -> tuple[str, str]:
    body = json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode()
    sha256 = hashlib.sha256(body).hexdigest()
    path = tmp_path / f"{sha256}.json"
    path.write_bytes(body)
    return str(path), sha256


def _seed_run(conn, run_id: str) -> None:
    conn.execute(
        "INSERT INTO engagements (id, name, org, created_at) VALUES (?, 'Acme', 'acme', '2026-01-01T00:00:00Z')",
        (f"e-{run_id}",),
    )
    conn.execute(
        """
        INSERT INTO runs (id, engagement_id, mode, playbook, repo, sha, status, scope_json, blast_radius)
        VALUES (?, ?, 'hunt', 'web-app.v1', 'acme/app', 'deadbeef', 'running', '{}', 'safe')
        """,
        (run_id, f"e-{run_id}"),
    )


def _seed_span(conn, run_id: str, result_sha256: str) -> None:
    conn.execute(
        "INSERT INTO tool_spans (id, run_id, agent, tool, args_hash, result_sha256, t) "
        "VALUES (?, ?, 'hunter', 'http_get', 'unused', ?, '2026-01-01T00:00:00Z')",
        (f"span-{run_id}-{result_sha256[:8]}", run_id, result_sha256),
    )


def _seed_hunt_finding(
    db_path: Path, fid: str, proof: dict, *, verdict: str = "true_positive", run_id: str | None = None
) -> None:
    consolidated = {
        "finding_id": fid,
        "mode": "hunt",
        "verdict": verdict,
        "confidence": 0.9,
        "vuln_class": "CWE-918",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "proof": proof,
        "scope": {"repo": "acme/app", "sha": "deadbeef"},
        "assumptions": ["admin session already authenticated"],
        "counterevidence": "would be falsified if /internal returned 403",
        "audit_trail": {
            "files_read": [],
            "commands_run": [],
            "tool_call_count": 1,
            "wall_time_seconds": 1.0,
        },
        "agent_meta": {"model": "test-model", "posture": "hunt", "pass_number": 1},
    }
    envelope = {"consolidated": consolidated}
    with db.session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO findings (id, repo_url, sha, rule_id, file, line, status, verdict_json, run_id)
            VALUES (?, 'acme/app', 'deadbeef', 'hunt.ssrf', 'app/internal.py', 10, 'verifying', ?, ?)
            """,
            (fid, json.dumps(envelope), run_id),
        )


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    p = tmp_path / "verifier-transcript-test.db"
    db.init_schema(p)
    return p


def test_http_replay_hash_match_passes_offline(db_path: Path, tmp_path: Path) -> None:
    artifact_uri, sha256 = _write_artifact(
        tmp_path, {"request": {"method": "GET", "url": "https://app.example/internal"}}
    )
    run_id = "run-http-ok"
    with db.session(db_path) as conn:
        _seed_run(conn, run_id)
        _seed_span(conn, run_id, sha256)
    proof = {
        "kind": "http_replay",
        "outcome": "exploited",
        "artifact_uri": artifact_uri,
        "artifact_sha256": sha256,
    }
    _seed_hunt_finding(db_path, "f-http-ok", proof, run_id=run_id)

    result = verifier.verify_finding("f-http-ok", db_path)

    assert result["replay"]["passed"] is True
    with db.session(db_path) as conn:
        row = conn.execute("SELECT status FROM findings WHERE id = ?", ("f-http-ok",)).fetchone()
    assert row["status"] == "needs_review"


def test_http_replay_hash_mismatch_fails_closed(db_path: Path, tmp_path: Path) -> None:
    artifact_uri, real_sha256 = _write_artifact(
        tmp_path, {"request": {"method": "GET", "url": "https://app.example/internal"}}
    )
    claimed_hash = "0" * 64
    run_id = "run-http-bad"
    with db.session(db_path) as conn:
        _seed_run(conn, run_id)
        # this run's gateway really did capture *something* hashing to
        # claimed_hash — the hunter just cited the wrong artifact file for it.
        _seed_span(conn, run_id, claimed_hash)
    proof = {
        "kind": "http_replay",
        "outcome": "exploited",
        "artifact_uri": artifact_uri,
        "artifact_sha256": claimed_hash,
    }
    _seed_hunt_finding(db_path, "f-http-bad", proof, run_id=run_id)

    result = verifier.verify_finding("f-http-bad", db_path)

    assert result["replay"]["passed"] is False
    assert "mismatch" in result["replay"]["error"]
    assert result["replay"]["artifact_sha256_actual"] == real_sha256
    with db.session(db_path) as conn:
        row = conn.execute("SELECT status FROM findings WHERE id = ?", ("f-http-bad",)).fetchone()
    assert row["status"] == "done"


def test_http_replay_missing_artifact_fails_closed(db_path: Path, tmp_path: Path) -> None:
    claimed_hash = "a" * 64
    run_id = "run-http-missing"
    with db.session(db_path) as conn:
        _seed_run(conn, run_id)
        _seed_span(conn, run_id, claimed_hash)
    proof = {
        "kind": "http_replay",
        "outcome": "exploited",
        "artifact_uri": str(tmp_path / "does-not-exist.json"),
        "artifact_sha256": claimed_hash,
    }
    _seed_hunt_finding(db_path, "f-http-missing", proof, run_id=run_id)

    result = verifier.verify_finding("f-http-missing", db_path)

    assert result["replay"]["passed"] is False
    assert "not found" in result["replay"]["error"]


def test_http_replay_rejects_hash_not_recorded_in_tool_spans(db_path: Path, tmp_path: Path) -> None:
    """The core provenance gate: a real, on-disk, hash-matching artifact

    still fails if this run's gateway never actually produced that hash —
    otherwise a hunter (or prompt-injected verdict) could point
    `artifact_uri` at an arbitrary readable file and have the verifier
    confirm its content and hash for free.
    """
    artifact_uri, sha256 = _write_artifact(
        tmp_path, {"request": {"method": "GET", "url": "https://app.example/whatever"}}
    )
    run_id = "run-http-unrecorded"
    with db.session(db_path) as conn:
        _seed_run(conn, run_id)
        # no tool_spans row — this run's gateway never captured this hash.
    proof = {
        "kind": "http_replay",
        "outcome": "exploited",
        "artifact_uri": artifact_uri,
        "artifact_sha256": sha256,
    }
    _seed_hunt_finding(db_path, "f-http-unrecorded", proof, run_id=run_id)

    result = verifier.verify_finding("f-http-unrecorded", db_path)

    assert result["replay"]["passed"] is False
    assert "not recorded" in result["replay"]["error"]


def test_http_replay_rejects_missing_run_id(db_path: Path, tmp_path: Path) -> None:
    artifact_uri, sha256 = _write_artifact(
        tmp_path, {"request": {"method": "GET", "url": "https://app.example/whatever"}}
    )
    proof = {
        "kind": "http_replay",
        "outcome": "exploited",
        "artifact_uri": artifact_uri,
        "artifact_sha256": sha256,
    }
    _seed_hunt_finding(db_path, "f-http-no-run", proof, run_id=None)

    result = verifier.verify_finding("f-http-no-run", db_path)

    assert result["replay"]["passed"] is False
    assert "run_id" in result["replay"]["error"]


def test_browser_trace_kind_uses_same_transcript_check(db_path: Path, tmp_path: Path) -> None:
    artifact_uri, sha256 = _write_artifact(
        tmp_path, {"request": {"method": "GET", "url": "https://app.example/admin"}}
    )
    run_id = "run-browser-ok"
    with db.session(db_path) as conn:
        _seed_run(conn, run_id)
        _seed_span(conn, run_id, sha256)
    proof = {
        "kind": "browser_trace",
        "outcome": "exploited",
        "artifact_uri": artifact_uri,
        "artifact_sha256": sha256,
    }
    _seed_hunt_finding(db_path, "f-browser-ok", proof, run_id=run_id)

    result = verifier.verify_finding("f-browser-ok", db_path)

    assert result["replay"]["passed"] is True


def test_unsupported_kind_does_not_touch_worktree(db_path: Path) -> None:
    proof = {"kind": "sandbox_transcript"}
    _seed_hunt_finding(db_path, "f-unsupported", proof, verdict="indeterminate")

    result = verifier.verify_finding("f-unsupported", db_path)

    assert result["replay"]["passed"] is False
    assert result["replay"]["error"] == "proof.kind is not a supported replay kind"
