"""Acceptance tests for the hunt playbook and the merge rule.

Offline: the specialist is injected, the transcript is canned, and the
verifier is the shipped one — no model call, no network, no docker.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from triage import db, hunt
from triage.config import REPO_ROOT


STAGE_IDS = [
    "recon",
    "knowledge",
    "spawn_specialists",
    "prove",
    "verify",
    "graph",
    "critic",
    "report",
]


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    p = tmp_path / "hunt-test.db"
    db.init_schema(p)
    return p


def _hunt_verdict() -> dict:
    return {
        "finding_id": "placeholder",
        "mode": "hunt",
        "verdict": "true_positive",
        "confidence": 0.8,
        "vuln_class": "CWE-89",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "proof": {
            "kind": "http_replay",
            "outcome": "exploited",
        },
        "scope": {"repo": hunt.FIXTURE_REPO_URL, "sha": hunt.FIXTURE_SHA},
        "assumptions": ["the gallery is reachable without a session"],
        "counterevidence": "a parameterised query would echo no SQL",
        "audit_trail": {
            "files_read": ["app/db.py:10-12"],
            "commands_run": [],
            "tool_call_count": 1,
            "wall_time_seconds": 0.5,
        },
        "agent_meta": {"model": "test-model", "posture": "hunt", "pass_number": 1},
    }


def _seed_scanner_row(db_path: Path, fid: str, file: str, line: int) -> None:
    with db.session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO findings (id, repo_url, sha, rule_id, file, line, status,
                                  source_kind, scanner_name, severity)
            VALUES (?, ?, ?, 'python.lang.security.sqli', ?, ?, 'queued',
                    'sast_csv', 'semgrep', 'High')
            """,
            (fid, hunt.FIXTURE_REPO_URL, hunt.FIXTURE_SHA, file, line),
        )


def _stored_verdict(db_path: Path, fid: str) -> dict:
    with db.session(db_path) as conn:
        row = conn.execute("SELECT verdict_json FROM findings WHERE id = ?", (fid,)).fetchone()
    return json.loads(row["verdict_json"])["consolidated"]


def test_load_playbook_has_five_classes_and_eight_stages() -> None:
    playbook = hunt.load_playbook()

    assert playbook["id"] == "web-app"
    assert playbook["version"] == 1
    assert tuple(playbook["classes"]) == hunt.CLASSES
    assert [stage["id"] for stage in playbook["stages"]] == STAGE_IDS
    caps = {stage["id"]: stage["cap"] for stage in playbook["stages"]}
    assert all(isinstance(cap, int) and cap >= 1 for cap in caps.values())
    assert caps["spawn_specialists"] == 5
    assert caps["prove"] == 3


@pytest.mark.parametrize(
    "body",
    [
        "id: web-app\nversion: 1\nclasses: [injection, xss, auth, authz, ssrf]\nstages: [recon, knowledge]\n",
        "id: web-app\nversion: 1\nclasses:\nstages: []\n",
        "- not\n- a mapping\n",
    ],
)
def test_load_playbook_rejects_malformed_shapes(tmp_path: Path, body: str) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(body, encoding="utf-8")

    with pytest.raises(ValueError):
        hunt.load_playbook(bad)


def test_load_playbook_rejects_a_renamed_stage(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "id: web-app\nversion: 1\n"
        "classes: [injection, xss, auth, authz, ssrf]\n"
        "stages:\n"
        + "".join(
            f"  - {{id: {sid if sid != 'recon' else 'reconnaissance'}, cap: 1}}\n"
            for sid in STAGE_IDS
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        hunt.load_playbook(bad)


def test_specialists_for_scale() -> None:
    assert hunt.specialists_for("sast") == ()
    assert hunt.specialists_for("one_class", vuln_class="injection") == ("injection",)
    assert hunt.specialists_for("full_app") == hunt.CLASSES

    with pytest.raises(ValueError):
        hunt.specialists_for("one_class", vuln_class="rce")
    with pytest.raises(ValueError):
        hunt.specialists_for("one_class")
    with pytest.raises(ValueError):
        hunt.specialists_for("org_wide")


def test_finding_id_is_stable() -> None:
    payload = "https://github.com/acme/app|deadbeef|injection|app/api.py:12|app/db.py:12"
    expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    assert (
        hunt.finding_id(
            "https://github.com/acme/app", "deadbeef", "injection",
            "app/api.py:12", "app/db.py:12",
        )
        == expected
    )
    moved = hunt.finding_id(
        "https://github.com/acme/app", "deadbeef", "injection",
        "app/api.py:12", "app/db.py:13",
    )
    assert moved != expected


def test_merge_keeps_scanner_row_and_attaches_proof(db_path: Path) -> None:
    _seed_scanner_row(db_path, "sast-1", "app/db.py", 12)

    fid = hunt.merge_or_insert(
        db_path=db_path,
        repo_url=hunt.FIXTURE_REPO_URL,
        sha=hunt.FIXTURE_SHA,
        vuln_class="injection",
        entry_file="app/api.py",
        entry_line=12,
        sink_file="app/db.py",
        sink_line=12,
        verdict=_hunt_verdict(),
        run_id="run-merge",
    )

    assert fid == "sast-1"
    with db.session(db_path) as conn:
        rows = conn.execute("SELECT * FROM findings").fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row["file"] == "app/db.py"
    assert row["line"] == 12
    assert row["rule_id"] == "python.lang.security.sqli"
    assert row["source_kind"] == "sast_csv"
    assert row["scanner_name"] == "semgrep"
    assert row["run_id"] == "run-merge"
    assert row["entry_location"] == "app/api.py:12"
    assert row["sink_location"] == "app/db.py:12"

    consolidated = _stored_verdict(db_path, fid)
    assert consolidated["proof"]["kind"] == "http_replay"
    assert "poc" not in consolidated
    assert consolidated["finding_id"] == "sast-1"


def test_merge_matches_on_entry_location_too(db_path: Path) -> None:
    _seed_scanner_row(db_path, "sast-entry", "app/api.py", 12)

    fid = hunt.merge_or_insert(
        db_path=db_path,
        repo_url=hunt.FIXTURE_REPO_URL,
        sha=hunt.FIXTURE_SHA,
        vuln_class="injection",
        entry_file="app/api.py",
        entry_line=12,
        sink_file="app/db.py",
        sink_line=12,
        verdict=_hunt_verdict(),
    )

    assert fid == "sast-entry"


def test_insert_when_no_scanner_row(db_path: Path) -> None:
    fid = hunt.merge_or_insert(
        db_path=db_path,
        repo_url=hunt.FIXTURE_REPO_URL,
        sha=hunt.FIXTURE_SHA,
        vuln_class="injection",
        entry_file="app/api.py",
        entry_line=12,
        sink_file="app/db.py",
        sink_line=12,
        verdict=_hunt_verdict(),
    )

    assert fid == hunt.finding_id(
        hunt.FIXTURE_REPO_URL, hunt.FIXTURE_SHA, "injection", "app/api.py:12", "app/db.py:12"
    )
    with db.session(db_path) as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
    assert row["source_kind"] == "hunt"
    assert row["rule_id"] == "hunt.injection"
    assert row["file"] == "app/api.py"
    assert row["line"] == 12
    assert row["status"] == "done"
    assert row["entry_location"] == "app/api.py:12"
    assert row["sink_location"] == "app/db.py:12"


def test_merge_or_insert_rejects_an_unknown_class(db_path: Path) -> None:
    with pytest.raises(ValueError):
        hunt.merge_or_insert(
            db_path=db_path,
            repo_url=hunt.FIXTURE_REPO_URL,
            sha=hunt.FIXTURE_SHA,
            vuln_class="rce",
            entry_file="app/api.py",
            entry_line=12,
            sink_file="app/db.py",
            sink_line=12,
            verdict=_hunt_verdict(),
        )


def test_hunter_passed_is_stripped(db_path: Path) -> None:
    verdict = _hunt_verdict()
    verdict["proof"]["replay"] = {"passed": True, "log_uri": None}

    fid = hunt.merge_or_insert(
        db_path=db_path,
        repo_url=hunt.FIXTURE_REPO_URL,
        sha=hunt.FIXTURE_SHA,
        vuln_class="injection",
        entry_file="app/api.py",
        entry_line=12,
        sink_file="app/db.py",
        sink_line=12,
        verdict=verdict,
    )

    consolidated = _stored_verdict(db_path, fid)
    assert "passed" not in consolidated["proof"]["replay"]


def test_hunter_poc_alias_is_dropped(db_path: Path) -> None:
    """A hunt row must never carry `poc`.

    `verifier.alias_poc_to_proof` would rebuild it as a `harness` proof
    and run `poc.command` in the merged row's worktree — command
    execution driven by text a black-box specialist wrote.
    """
    _seed_scanner_row(db_path, "sast-poc", "app/db.py", 12)
    verdict = _hunt_verdict()
    verdict["poc"] = {
        "path": "poc/x",
        "command": "python -c 'print(1)'",
        "exit_code": 0,
        "evidence_excerpt": "1",
    }

    fid = hunt.merge_or_insert(
        db_path=db_path,
        repo_url=hunt.FIXTURE_REPO_URL,
        sha=hunt.FIXTURE_SHA,
        vuln_class="injection",
        entry_file="app/api.py",
        entry_line=12,
        sink_file="app/db.py",
        sink_line=12,
        verdict=verdict,
    )

    consolidated = _stored_verdict(db_path, fid)
    assert "poc" not in consolidated
    assert consolidated["proof"]["kind"] == "http_replay"


def test_fixture_transcript_reaches_needs_review(db_path: Path, tmp_path: Path) -> None:
    result = hunt.run_fixture(db_path=db_path, transcripts_dir=tmp_path)

    assert len(result["finding_ids"]) == 1
    fid = result["finding_ids"][0]
    assert result["statuses"][fid] == "needs_review"

    with db.session(db_path) as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
        spans = conn.execute(
            "SELECT result_sha256 FROM tool_spans WHERE run_id = ?", (row["run_id"],)
        ).fetchall()
        run = conn.execute("SELECT * FROM runs WHERE id = ?", (row["run_id"],)).fetchone()
    assert row["status"] == "needs_review"
    assert row["source_kind"] == "hunt"
    assert (run["mode"], run["playbook"], run["status"]) == ("hunt", hunt.PLAYBOOK_ID, "running")

    verifier_result = json.loads(row["verifier_json"])
    assert verifier_result["replay"]["passed"] is True
    assert verifier_result["replay"]["kind"] == "http_replay"

    proof = json.loads(row["verdict_json"])["consolidated"]["proof"]
    assert proof["artifact_sha256"] in {s["result_sha256"] for s in spans}
    artifact = Path(proof["artifact_uri"])
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == proof["artifact_sha256"]


def test_fixture_merges_onto_a_seeded_scanner_row(db_path: Path, tmp_path: Path) -> None:
    _seed_scanner_row(db_path, "sast-fixture", "app/db.py", hunt.FIXTURE_SINK_LINE)

    result = hunt.run_fixture(db_path=db_path, transcripts_dir=tmp_path)

    assert result["finding_ids"] == ["sast-fixture"]
    with db.session(db_path) as conn:
        rows = conn.execute("SELECT id, status, rule_id FROM findings").fetchall()
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "python.lang.security.sqli"
    assert rows[0]["status"] == "needs_review"


def test_no_finding_is_published(db_path: Path, tmp_path: Path) -> None:
    hunt.run_fixture(db_path=db_path, transcripts_dir=tmp_path)

    with db.session(db_path) as conn:
        statuses = [r["status"] for r in conn.execute("SELECT status FROM findings")]
    assert statuses
    assert "published" not in statuses


def test_failed_hash_stays_done(db_path: Path, tmp_path: Path) -> None:
    def specialist(vuln_class: str):
        if vuln_class != "injection":
            return None
        hypothesis = hunt.default_specialist("injection")
        hypothesis["verdict"]["proof"]["artifact_sha256"] = "0" * 64
        return hypothesis

    result = hunt.run_fixture(db_path=db_path, specialist=specialist, transcripts_dir=tmp_path)

    fid = result["finding_ids"][0]
    assert result["statuses"][fid] == "done"
    with db.session(db_path) as conn:
        row = conn.execute("SELECT verifier_json FROM findings WHERE id = ?", (fid,)).fetchone()
    assert json.loads(row["verifier_json"])["replay"]["passed"] is False


def test_sast_scale_runs_no_specialist(db_path: Path, tmp_path: Path) -> None:
    result = hunt.run_fixture(db_path=db_path, scale="sast", transcripts_dir=tmp_path)

    assert result == {"finding_ids": [], "statuses": {}}
    with db.session(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"] == 0


def test_full_app_asks_every_class(db_path: Path, tmp_path: Path) -> None:
    asked: list[str] = []

    def specialist(vuln_class: str):
        asked.append(vuln_class)
        return hunt.default_specialist(vuln_class)

    hunt.run_fixture(db_path=db_path, specialist=specialist, transcripts_dir=tmp_path)

    assert tuple(asked) == hunt.CLASSES


def test_every_playbook_class_has_a_specialist_prompt() -> None:
    for vuln_class in hunt.CLASSES:
        prompt = REPO_ROOT / "prompts" / f"hunt-{vuln_class}.prompt.md"
        assert prompt.is_file(), f"missing prompt for {vuln_class}"
        text = prompt.read_text(encoding="utf-8")
        assert "proof.replay.passed" in text
        assert f"vuln_class: {vuln_class}" in text
