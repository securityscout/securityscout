"""Hunt mode: playbook, class specialists, and the scanner merge rule.

A hunt finding lands in the same `findings` table as an ingested SAST
row. When the hunt located the same code, the scanner row wins on
identity and location and only gains the proof — one row, one ticket.

This module never writes `needs_review` or `published`. It writes a
verdict and hands the finding to `triage.verifier`, which owns
`proof.replay.passed`.

CLI:
    python -m triage.hunt [--playbook PATH] [--scale SCALE] [--vuln-class CLASS]
        Print the playbook stages and the specialists that scale spawns.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import yaml

from triage.config import REPO_ROOT
from triage.db import init_schema, session
from triage.gateway import canonical_json_bytes
from triage.status import cas_status
from triage.verifier import strip_replay_passed, verify_finding

CLASSES = ("injection", "xss", "auth", "authz", "ssrf")
SCALES = ("sast", "one_class", "full_app")

PLAYBOOK_PATH = REPO_ROOT / "playbooks" / "web-app.v1.yaml"
PLAYBOOK_ID = "web-app.v1"

_STAGE_IDS = (
    "recon",
    "knowledge",
    "spawn_specialists",
    "prove",
    "verify",
    "graph",
    "critic",
    "report",
)

FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "hunt"
FIXTURE_REPO_URL = "https://github.com/acme/photoview-class"
FIXTURE_SHA = "9f1c0a7b2d4e6f80112233445566778899aabbcc"
FIXTURE_CLASS = "injection"
FIXTURE_ENTRY_FILE = "app/api.py"
FIXTURE_ENTRY_LINE = 12
FIXTURE_SINK_FILE = "app/db.py"
FIXTURE_SINK_LINE = 12
_CANNED_TRANSCRIPT = FIXTURE_ROOT / "transcripts" / "injection-search.json"


def finding_id(repo_url: str, sha: str, vuln_class: str, entry: str, sink: str) -> str:
    """Hunt identity. `entry` and `sink` are `file:line`."""
    payload = f"{repo_url}|{sha}|{vuln_class}|{entry}|{sink}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def specialists_for(scale: str, *, vuln_class: str | None = None) -> tuple[str, ...]:
    """Which class agents a scale spawns.

    The scale rule lives here, not only in the orchestrator prompt: a
    model asked "how many agents?" answers generously, and a single SAST
    row does not get five.
    """
    if scale == "sast":
        return ()
    if scale == "one_class":
        if vuln_class not in CLASSES:
            raise ValueError(f"one_class needs a vuln_class in {CLASSES}, got {vuln_class!r}")
        return (vuln_class,)
    if scale == "full_app":
        return CLASSES
    raise ValueError(f"unknown scale: {scale!r}; want one of {SCALES}")


def load_playbook(path: Path | str | None = None) -> dict:
    playbook = yaml.safe_load(Path(path or PLAYBOOK_PATH).read_text(encoding="utf-8"))
    if not isinstance(playbook, dict):
        raise ValueError("playbook is not a mapping")
    missing = {"id", "version", "classes", "stages"} - set(playbook)
    if missing:
        raise ValueError(f"playbook missing keys: {sorted(missing)}")
    classes = playbook["classes"]
    if not isinstance(classes, list) or tuple(classes) != CLASSES:
        raise ValueError(f"playbook classes must be {list(CLASSES)}")
    stages = playbook["stages"]
    if not isinstance(stages, list) or not all(isinstance(s, dict) for s in stages):
        raise ValueError("playbook stages must be a list of mappings")
    if tuple(s.get("id") for s in stages) != _STAGE_IDS:
        raise ValueError(f"playbook stages must be {list(_STAGE_IDS)} in that order")
    for stage in stages:
        cap = stage.get("cap")
        if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
            raise ValueError(f"stage {stage['id']} needs an integer cap >= 1")
    return playbook


def _location(file: str, line: int) -> str:
    return f"{file}:{line}"


def merge_or_insert(
    *,
    db_path: Path | str,
    repo_url: str,
    sha: str,
    vuln_class: str,
    entry_file: str,
    entry_line: int,
    sink_file: str,
    sink_line: int,
    verdict: dict,
    run_id: str | None = None,
) -> str:
    """Attach a hunt verdict to the scanner row it found, or insert one.

    `verdict` is the consolidated verdict; it is stored wrapped as
    `{"consolidated": ...}` because that is the envelope the verifier
    reads. Its `finding_id` is rewritten to the row's real id — on a
    merge the hunter cannot know the scanner's id.

    A hunt writer emits `proof` only. The deprecated `poc` alias is
    dropped rather than stored: on a verdict that declares no `proof`,
    `verifier.alias_poc_to_proof` rebuilds one with `kind: harness` and
    the verifier then runs `poc.command` as a subprocess in the merged
    row's worktree. A hunt specialist reads attacker-controlled HTTP
    responses, so that is a command-execution path reachable from a
    prompt-injected verdict — and it is not the explicit, SoT-sanctioned
    harness proof, which names its own `proof.kind`.
    """
    if vuln_class not in CLASSES:
        raise ValueError(f"vuln_class must be one of {CLASSES}, got {vuln_class!r}")

    entry = _location(entry_file, entry_line)
    sink = _location(sink_file, sink_line)
    consolidated = strip_replay_passed(copy.deepcopy(verdict))
    consolidated.pop("poc", None)

    with session(db_path) as conn:
        match = conn.execute(
            """
            SELECT id FROM findings
             WHERE repo_url = ? AND sha = ?
               AND ((file = ? AND line = ?) OR (file = ? AND line = ?))
             ORDER BY id LIMIT 1
            """,
            (repo_url, sha, sink_file, sink_line, entry_file, entry_line),
        ).fetchone()

        fid = match["id"] if match else finding_id(repo_url, sha, vuln_class, entry, sink)
        consolidated["finding_id"] = fid
        envelope = json.dumps({"consolidated": consolidated}, ensure_ascii=False)

        if match:
            conn.execute(
                """
                UPDATE findings
                   SET entry_location = ?, sink_location = ?, verdict_json = ?,
                       run_id = COALESCE(?, run_id)
                 WHERE id = ?
                """,
                (entry, sink, envelope, run_id, fid),
            )
        else:
            conn.execute(
                """
                INSERT INTO findings (id, repo_url, sha, rule_id, file, line, status,
                                      source_kind, run_id, entry_location, sink_location,
                                      verdict_json)
                VALUES (?, ?, ?, ?, ?, ?, 'done', 'hunt', ?, ?, ?, ?)
                """,
                (fid, repo_url, sha, f"hunt.{vuln_class}", entry_file, entry_line,
                 run_id, entry, sink, envelope),
            )
    return fid


def default_specialist(vuln_class: str) -> dict | None:
    """Fixture stand-in for a class agent.

    Only `injection` returns a hypothesis this slice, so acceptance does
    not depend on five live proofs. A real specialist is a model call
    behind the tool gateway and returns the same shape.
    """
    if vuln_class != FIXTURE_CLASS:
        return None
    return {
        "vuln_class": FIXTURE_CLASS,
        "entry_file": FIXTURE_ENTRY_FILE,
        "entry_line": FIXTURE_ENTRY_LINE,
        "sink_file": FIXTURE_SINK_FILE,
        "sink_line": FIXTURE_SINK_LINE,
        "verdict": {
            "finding_id": "pending",
            "mode": "hunt",
            "verdict": "true_positive",
            "confidence": 0.85,
            "vuln_class": "CWE-89",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "proof": {"kind": "http_replay", "outcome": "exploited"},
            "scope": {"repo": FIXTURE_REPO_URL, "sha": FIXTURE_SHA},
            "assumptions": ["/api/search is reachable without a session"],
            "counterevidence": (
                "a parameterised query would not echo the search term inside SQL"
            ),
            "audit_trail": {
                "files_read": [
                    f"{FIXTURE_ENTRY_FILE}:{FIXTURE_ENTRY_LINE}",
                    f"{FIXTURE_SINK_FILE}:{FIXTURE_SINK_LINE}",
                ],
                "commands_run": [],
                "tool_call_count": 1,
                "wall_time_seconds": 0.4,
            },
            "agent_meta": {"model": "fixture", "posture": "hunt", "pass_number": 1},
        },
    }


def _canned_transcript() -> dict:
    return json.loads(_CANNED_TRANSCRIPT.read_text(encoding="utf-8"))


def _record_proof(
    conn,
    *,
    run_id: str,
    proof: dict,
    transcript: dict,
    transcripts_dir: Path,
) -> None:
    """Persist the transcript and the span that vouches for it.

    Stands in for `gateway.invoke` + `http_session.gateway_execute`,
    which would have sent the request: same bytes on disk as in the span,
    same `<sha256>.json` naming. The span carries the hash of the bytes
    actually written, never the one the hypothesis declared — a hunter
    naming a hash this run did not produce is exactly what the verifier's
    provenance gate exists to reject.
    """
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
    proof.setdefault("artifact_uri", str(artifact))
    proof.setdefault("artifact_sha256", digest)


def _to_verifying(db_path: Path | str, fid: str) -> None:
    """Hand the row to the verifier through the legal hops.

    A hunt row is written `done` and a merged scanner row is wherever
    ingest left it; both reach `verifying` through `triaging`, the only
    edge the state machine offers.
    """
    with session(db_path) as conn:
        row = conn.execute("SELECT status FROM findings WHERE id = ?", (fid,)).fetchone()
        if row["status"] != "triaging":
            cas_status(conn, fid, row["status"], "triaging")
        cas_status(conn, fid, "triaging", "verifying")


def run_fixture(
    *,
    db_path: Path | str,
    scale: str = "full_app",
    specialist: Callable[[str], dict | None] | None = None,
    verify: Callable[[str], Any] | None = None,
    transcripts_dir: Path | str | None = None,
) -> dict:
    """Drive the playbook end to end against the in-tree fixture.

    The engagement, run, transcript and span are written here rather than
    in a test so the provenance chain the verifier checks is the one this
    module really produces.
    """
    init_schema(db_path)
    specialist = specialist or default_specialist
    out_dir = Path(transcripts_dir) if transcripts_dir else FIXTURE_ROOT / "transcripts"

    classes = specialists_for(scale, vuln_class=FIXTURE_CLASS if scale == "one_class" else None)
    if not classes:
        return {"finding_ids": [], "statuses": {}}

    transcript = _canned_transcript()
    host = urlparse(transcript["request"]["url"]).hostname or ""
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    engagement_id = f"eng-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    with session(db_path) as conn:
        conn.execute(
            "INSERT INTO engagements (id, name, org, created_at) VALUES (?, ?, ?, ?)",
            (engagement_id, "photoview-class fixture", "acme", now),
        )
        conn.execute(
            """
            INSERT INTO runs (id, engagement_id, mode, playbook, repo, sha, status,
                              started_at, scope_json, blast_radius)
            VALUES (?, ?, 'hunt', ?, ?, ?, 'running', ?, ?, 'safe')
            """,
            (run_id, engagement_id, PLAYBOOK_ID, FIXTURE_REPO_URL,
             FIXTURE_SHA, now, json.dumps({"repos": [FIXTURE_REPO_URL], "hosts": [host]})),
        )

    finding_ids: list[str] = []
    for vuln_class in classes:
        hypothesis = specialist(vuln_class)
        if hypothesis is None:
            continue
        verdict = hypothesis["verdict"]
        with session(db_path) as conn:
            _record_proof(
                conn,
                run_id=run_id,
                proof=verdict["proof"],
                transcript=transcript,
                transcripts_dir=out_dir,
            )
        finding_ids.append(
            merge_or_insert(
                db_path=db_path,
                repo_url=FIXTURE_REPO_URL,
                sha=FIXTURE_SHA,
                vuln_class=hypothesis["vuln_class"],
                entry_file=hypothesis["entry_file"],
                entry_line=hypothesis["entry_line"],
                sink_file=hypothesis["sink_file"],
                sink_line=hypothesis["sink_line"],
                verdict=verdict,
                run_id=run_id,
            )
        )

    verify = verify or (lambda fid: verify_finding(fid, db_path))
    statuses: dict[str, str] = {}
    for fid in finding_ids:
        _to_verifying(db_path, fid)
        verify(fid)
        with session(db_path) as conn:
            row = conn.execute("SELECT status FROM findings WHERE id = ?", (fid,)).fetchone()
        statuses[fid] = row["status"]
    return {"finding_ids": finding_ids, "statuses": statuses}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.hunt")
    parser.add_argument("--playbook", default=None)
    parser.add_argument("--scale", default="full_app", choices=SCALES)
    parser.add_argument("--vuln-class", default=None, choices=CLASSES)
    args = parser.parse_args(argv)

    playbook = load_playbook(args.playbook)
    print(f"{playbook['id']}.v{playbook['version']}")
    for stage in playbook["stages"]:
        print(f"  {stage['id']:<18} cap={stage['cap']}")
    specialists = specialists_for(args.scale, vuln_class=args.vuln_class)
    print(f"scale={args.scale} spawns {len(specialists)}: {', '.join(specialists) or 'none'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
