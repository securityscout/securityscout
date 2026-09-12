"""Chain hops: the edges that turn two findings into an attack path.

A hop is evidence that one finding reached another — a session reused
against an admin endpoint, a credential replayed, an SSRF pivot. The
reporter scores the path, so the edge carries its own evidence URI and
never borrows a finding's proof.

The fixture chain is seeded here rather than in a test: the transcript,
the span that vouches for it and the two findings it links are the ones
this module really writes.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from triage.config import REPO_ROOT
from triage.db import init_schema, session
from triage.gateway import canonical_json_bytes

HOP_KINDS = ("cred", "session", "object_id", "ssrf_pivot", "rce_exec", "info")

FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "graph"
FIXTURE_REPO_URL = "https://github.com/acme/graph-fixture"
FIXTURE_SHA = "a" * 40
FIXTURE_PLAYBOOK = "web-app.v1"
_CANNED_TRANSCRIPT = FIXTURE_ROOT / "session-admin.json"

_FROM_RULE = "hunt.session"
_FROM_FILE = "app/auth.py"
_FROM_LINE = 34
_TO_RULE = "hunt.admin"
_TO_FILE = "app/admin.py"
_TO_LINE = 8


def record_hop(
    *,
    db_path: Path | str,
    from_id: str,
    to_id: str,
    kind: str,
    evidence_uri: str,
) -> str:
    """Link two existing findings. Returns the hop id."""
    if kind not in HOP_KINDS:
        raise ValueError(f"kind must be one of {HOP_KINDS}, got {kind!r}")

    hop_id = uuid.uuid4().hex
    with session(db_path) as conn:
        for endpoint in (from_id, to_id):
            row = conn.execute(
                "SELECT 1 FROM findings WHERE id = ?", (endpoint,)
            ).fetchone()
            if row is None:
                raise ValueError(f"no such finding: {endpoint!r}")
        conn.execute(
            "INSERT INTO chain_hops (id, from_id, to_id, kind, evidence_uri) "
            "VALUES (?, ?, ?, ?, ?)",
            (hop_id, from_id, to_id, kind, evidence_uri),
        )
    return hop_id


def _record_transcript(conn, *, run_id: str, transcripts_dir: Path) -> Path:
    """Persist the canned transcript and the span that vouches for it.

    Stands in for `gateway.invoke` + `http_session.gateway_execute`, which
    would have sent the request: same bytes on disk as in the span, same
    `<sha256>.json` naming. The span carries the hash of the bytes actually
    written, never one the seed declared — a hop naming a hash this run did
    not produce is what the provenance gate exists to reject.
    """
    transcript = json.loads(_CANNED_TRANSCRIPT.read_text(encoding="utf-8"))
    request = transcript["request"]
    body = canonical_json_bytes(transcript)
    digest = hashlib.sha256(body).hexdigest()
    transcripts_dir.mkdir(parents=True, exist_ok=True)
    artifact = transcripts_dir / f"{digest}.json"
    artifact.write_bytes(body)

    args = {"method": request["method"], "url": request["url"]}
    conn.execute(
        "INSERT INTO tool_spans (id, run_id, agent, tool, args_hash, result_sha256, t) "
        "VALUES (?, ?, 'hunter', 'http_get', ?, ?, ?)",
        (
            uuid.uuid4().hex,
            run_id,
            hashlib.sha256(canonical_json_bytes(args)).hexdigest(),
            digest,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    return artifact


def _insert_finding(conn, *, run_id: str, rule_id: str, file: str, line: int) -> str:
    finding_id = uuid.uuid4().hex
    conn.execute(
        """
        INSERT INTO findings (id, repo_url, sha, rule_id, file, line, status,
                              source_kind, run_id)
        VALUES (?, ?, ?, ?, ?, ?, 'done', 'hunt', ?)
        """,
        (finding_id, FIXTURE_REPO_URL, FIXTURE_SHA, rule_id, file, line, run_id),
    )
    return finding_id


def seed_two_hop(
    *,
    db_path: Path | str,
    transcripts_dir: Path | str | None = None,
) -> dict:
    """Write the leaked-session → admin-endpoint fixture chain.

    One engagement, one done run, two findings and the single `session`
    hop between them. Nothing here reaches `needs_review` or `published`:
    a hop is not a review decision.
    """
    init_schema(db_path)
    out_dir = Path(transcripts_dir) if transcripts_dir else FIXTURE_ROOT / "transcripts"

    engagement_id = f"eng-{uuid.uuid4().hex[:12]}"
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    with session(db_path) as conn:
        conn.execute(
            "INSERT INTO engagements (id, name, org, created_at) VALUES (?, ?, ?, ?)",
            (engagement_id, "graph-fixture", "acme", now),
        )
        conn.execute(
            """
            INSERT INTO runs (id, engagement_id, mode, playbook, repo, sha, status,
                              started_at, ended_at, scope_json, blast_radius)
            VALUES (?, ?, 'hunt', ?, ?, ?, 'done', ?, ?, '{}', 'safe')
            """,
            (run_id, engagement_id, FIXTURE_PLAYBOOK, FIXTURE_REPO_URL, FIXTURE_SHA,
             now, now),
        )
        artifact = _record_transcript(conn, run_id=run_id, transcripts_dir=out_dir)
        from_id = _insert_finding(
            conn, run_id=run_id, rule_id=_FROM_RULE, file=_FROM_FILE, line=_FROM_LINE
        )
        to_id = _insert_finding(
            conn, run_id=run_id, rule_id=_TO_RULE, file=_TO_FILE, line=_TO_LINE
        )

    hop_id = record_hop(
        db_path=db_path,
        from_id=from_id,
        to_id=to_id,
        kind="session",
        evidence_uri=str(artifact),
    )
    return {
        "engagement_id": engagement_id,
        "run_id": run_id,
        "from_id": from_id,
        "to_id": to_id,
        "hop_id": hop_id,
    }
