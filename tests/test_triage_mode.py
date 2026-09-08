"""Seeded triage mode: two-pass worker + harness verifier."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from triage import db
from triage.config import REPO_ROOT

_HARNESS = f"{sys.executable} harness.py"


def _tp_verdict(finding_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "mode": "triage",
        "verdict": "true_positive",
        "confidence": 0.9,
        "actual_sink_location": "app.py:5",
        "vuln_class": "CWE-89",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "taint_trace": [
            {"step": "source", "file": "app.py", "line": 5, "note": "user_id argument"},
            {"step": "sink", "file": "app.py", "line": 5, "note": "f-string SQL"},
        ],
        "sanitizers_in_path": [],
        "proof": {
            "kind": "harness",
            "outcome": "exploited",
            "artifact_uri": "harness.py",
            "replay": {"command": _HARNESS, "exit_code": 0, "passed": True},
        },
        "audit_trail": {
            "files_read": ["app.py:1-5"],
            "commands_run": [_HARNESS],
            "tool_call_count": 2,
            "wall_time_seconds": 1,
        },
        "agent_meta": {"model": "test-pass1", "posture": "argue_tp", "pass_number": 1},
    }


def _fp_verdict(finding_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "mode": "triage",
        "verdict": "false_positive",
        "confidence": 0.91,
        "actual_sink_location": "app.py:7",
        "vuln_class": "CWE-79",
        "cvss_vector": None,
        "taint_trace": [
            {"step": "source", "file": "app.py", "line": 7, "note": "name argument"},
            {"step": "sanitizer", "file": "app.py", "line": 7, "note": "html.escape"},
            {"step": "sink", "file": "app.py", "line": 7, "note": "HTML string"},
        ],
        "sanitizers_in_path": [
            {
                "file": "app.py",
                "line": 7,
                "function": "html.escape",
                "applied_to": "name",
                "sufficient_for_class": True,
                "reason": "html.escape converts angle brackets before the string is returned",
            }
        ],
        "proof": {
            "kind": "harness",
            "outcome": "blocked",
            "artifact_uri": "harness.py",
            "replay": {"command": _HARNESS, "exit_code": 0, "passed": True},
        },
        "blocker": {
            "file": "app.py",
            "line": 7,
            "construct": "html.escape(name)",
            "reasoning": "The renderer HTML-escapes name before interpolation; the harness shows <script> does not survive.",
        },
        "audit_trail": {
            "files_read": ["app.py:1-7"],
            "commands_run": [_HARNESS],
            "tool_call_count": 2,
            "wall_time_seconds": 1,
        },
        "agent_meta": {"model": "test-pass2", "posture": "argue_fp", "pass_number": 2},
    }


def _recon_doc() -> dict:
    return {
        "languages": [{"name": "Python", "lines": 8, "pct": 100}],
        "frameworks": [],
        "package_manifests": [],
        "route_table": [],
        "sink_inventory": {},
        "trust_boundaries": [],
        "osv_scan": {},
        "notes": "synthetic fixture",
    }


def test_argue_fp_render_includes_finding_tokens(tmp_path: Path) -> None:
    from triage import seeds
    from triage.triage_worker import _ARGUE_FP, _render_prompt, _row_dict

    db_path = tmp_path / "triage.db"
    db.init_schema(db_path)
    seed = next(s for s in seeds.load_known() if s.expected == "false_positive")
    with db.session(db_path) as conn:
        fid = seeds.insert_seed(conn, seed)
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
        finding = _row_dict(row)

    worktree = REPO_ROOT / seed.worktree
    recon = _recon_doc()
    template = _ARGUE_FP.read_text(encoding="utf-8")
    for token in (
        "{{FINDING_ID}}",
        "{{REPO_LOCAL}}",
        "{{SHA}}",
        "{{FILE}}",
        "{{LINE}}",
        "{{RULE_ID}}",
        "{{SEVERITY}}",
        "{{DESCRIPTION}}",
        "{{SCANNER_URL}}",
        "{{RECON_JSON}}",
    ):
        assert token in template

    text = _render_prompt(_ARGUE_FP, finding, recon, worktree)
    assert fid in text
    assert str(worktree) in text
    assert seed.sha in text
    assert seed.file in text
    assert str(seed.line) in text
    assert seed.rule_id in text
    assert seed.severity in text
    assert seed.description in text
    assert json.dumps(recon, ensure_ascii=False) in text
    for token in (
        "{{FINDING_ID}}",
        "{{REPO_LOCAL}}",
        "{{SHA}}",
        "{{FILE}}",
        "{{LINE}}",
        "{{RULE_ID}}",
        "{{SEVERITY}}",
        "{{DESCRIPTION}}",
        "{{SCANNER_URL}}",
        "{{RECON_JSON}}",
    ):
        assert token not in text


def test_main_exits_1_on_unexpected_error_after_row_is_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from triage import seeds, triage_worker

    db_path = tmp_path / "triage.db"
    db.init_schema(db_path)
    seed = next(s for s in seeds.load_known() if s.expected == "true_positive")
    with db.session(db_path) as conn:
        fid = seeds.insert_seed(conn, seed)

    def boom(ctx: object) -> dict:
        raise KeyError("missing")

    monkeypatch.setattr(triage_worker, "_default_spawn", boom)
    code = triage_worker.main(
        ["--db", str(db_path), "--finding-id", fid, "--workdir", str(REPO_ROOT / seed.worktree)]
    )
    assert code == 1
    err = capsys.readouterr().err.strip()
    assert err
    assert "\n" not in err
    with db.session(db_path) as conn:
        status = conn.execute("SELECT status FROM findings WHERE id = ?", (fid,)).fetchone()["status"]
    assert status == "error"


def test_seeded_tp_and_fp_get_right_verdict_with_harness_replay(tmp_path: Path) -> None:
    from triage import recon, seeds, triage_worker, verifier

    known = seeds.load_known()
    tps = [s for s in known if s.expected == "true_positive"]
    fps = [s for s in known if s.expected == "false_positive"]
    assert len(tps) >= 1
    assert len(fps) >= 1

    db_path = tmp_path / "triage.db"
    db.init_schema(db_path)
    cache_dir = tmp_path / "cache"
    verdicts_dir = tmp_path / "verdicts"

    inserted: dict[str, str] = {}
    with db.session(db_path) as conn:
        for seed in known:
            inserted[seed.expected] = seeds.insert_seed(conn, seed)

    def spawn_recon(prompt: str, model: str, cwd: Path) -> dict:
        del prompt, model, cwd
        return _recon_doc()

    def spawn_agent(ctx: object) -> dict:
        finding = ctx.finding  # type: ignore[attr-defined]
        posture = ctx.posture  # type: ignore[attr-defined]
        fid = finding["id"]
        if finding["rule_id"] == "python.sql.injection":
            out = _tp_verdict(fid)
        else:
            out = _fp_verdict(fid)
        out["agent_meta"]["posture"] = posture
        out["agent_meta"]["pass_number"] = 1 if posture == "argue_tp" else 2
        return out

    for seed in known:
        worktree = REPO_ROOT / seed.worktree
        recon.ensure_recon(
            seed.repo_url,
            seed.sha,
            worktree,
            db_path=db_path,
            cache_dir=cache_dir,
            spawn=spawn_recon,
        )
        fid = inserted[seed.expected]
        triage_worker.triage_finding(
            fid,
            db_path,
            worktree=worktree,
            spawn=spawn_agent,
            verdicts_dir=verdicts_dir,
        )
        with db.session(db_path) as conn:
            row = conn.execute(
                "SELECT verdict_json, status FROM findings WHERE id = ?", (fid,)
            ).fetchone()
        envelope = json.loads(row["verdict_json"])
        replay = envelope["consolidated"]["proof"]["replay"]
        assert "passed" not in replay
        assert row["status"] == "verifying"

        verifier.verify_finding(fid, db_path, worktree=worktree)

    with db.session(db_path) as conn:
        tp = conn.execute(
            "SELECT status, verdict_json FROM findings WHERE id = ?",
            (inserted["true_positive"],),
        ).fetchone()
        fp = conn.execute(
            "SELECT status, verdict_json FROM findings WHERE id = ?",
            (inserted["false_positive"],),
        ).fetchone()

    tp_cons = json.loads(tp["verdict_json"])["consolidated"]
    fp_cons = json.loads(fp["verdict_json"])["consolidated"]
    assert tp_cons["verdict"] == "true_positive"
    assert tp_cons["proof"]["replay"]["passed"] is True
    assert tp["status"] == "needs_review"
    assert fp_cons["verdict"] == "false_positive"
    assert fp_cons["proof"]["replay"]["passed"] is True
    assert fp["status"] == "done"


def test_spawn_failure_moves_triaging_to_error(tmp_path: Path) -> None:
    from triage import seeds, triage_worker

    db_path = tmp_path / "triage.db"
    db.init_schema(db_path)
    seed = next(s for s in seeds.load_known() if s.expected == "true_positive")
    with db.session(db_path) as conn:
        fid = seeds.insert_seed(conn, seed)

    def boom(ctx: object) -> dict:
        raise RuntimeError("agent down")

    try:
        triage_worker.triage_finding(
            fid,
            db_path,
            worktree=REPO_ROOT / seed.worktree,
            spawn=boom,
            verdicts_dir=tmp_path / "verdicts",
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("spawn should raise")

    with db.session(db_path) as conn:
        status = conn.execute("SELECT status FROM findings WHERE id = ?", (fid,)).fetchone()["status"]
    assert status == "error"


def test_worker_does_not_write_verdict_unless_still_triaging(tmp_path: Path) -> None:
    from triage import seeds, triage_worker
    from triage.status import TransitionConflict

    db_path = tmp_path / "triage.db"
    db.init_schema(db_path)
    seed = next(s for s in seeds.load_known() if s.expected == "true_positive")
    with db.session(db_path) as conn:
        fid = seeds.insert_seed(conn, seed)

    def spawn(ctx: object) -> dict:
        finding = ctx.finding  # type: ignore[attr-defined]
        if ctx.posture == "argue_fp":  # type: ignore[attr-defined]
            with db.session(db_path) as conn:
                conn.execute("UPDATE findings SET status = 'error' WHERE id = ?", (fid,))
        return _tp_verdict(finding["id"])

    try:
        triage_worker.triage_finding(
            fid,
            db_path,
            worktree=REPO_ROOT / seed.worktree,
            spawn=spawn,
            verdicts_dir=tmp_path / "verdicts",
        )
    except TransitionConflict:
        pass
    else:
        raise AssertionError("write should conflict if no longer triaging")

    with db.session(db_path) as conn:
        row = conn.execute(
            "SELECT status, verdict_json FROM findings WHERE id = ?", (fid,)
        ).fetchone()
    assert row["status"] == "error"
    assert row["verdict_json"] is None


def test_consolidate_keeps_the_agreeing_tp_that_has_a_harness() -> None:
    from triage.triage_worker import consolidate

    bare = _tp_verdict("a")
    bare["proof"]["replay"].pop("command", None)
    with_harness = _tp_verdict("b")
    out = consolidate(bare, with_harness)
    assert out["proof"]["replay"]["command"] == _HARNESS


def test_verify_refuses_non_harness_kind(tmp_path: Path) -> None:
    from triage import seeds, verifier

    db_path = tmp_path / "triage.db"
    db.init_schema(db_path)
    seed = next(s for s in seeds.load_known() if s.expected == "true_positive")
    marker = tmp_path / "RAN"
    with db.session(db_path) as conn:
        fid = seeds.insert_seed(conn, seed)
        verdict = _tp_verdict(fid)
        verdict["proof"]["kind"] = "http_replay"
        verdict["proof"]["replay"]["command"] = (
            f"{sys.executable} -c \"from pathlib import Path; Path({str(marker)!r}).write_text('x')\""
        )
        envelope = {"pass1": verdict, "pass2": verdict, "consolidated": verdict}
        conn.execute(
            "UPDATE findings SET status = 'verifying', verdict_json = ? WHERE id = ?",
            (json.dumps(envelope), fid),
        )

    result = verifier.verify_finding(fid, db_path, worktree=REPO_ROOT / seed.worktree)
    assert result["replay"]["passed"] is False
    assert not marker.exists()
    with db.session(db_path) as conn:
        status = conn.execute("SELECT status FROM findings WHERE id = ?", (fid,)).fetchone()["status"]
    assert status == "done"


def test_verify_does_not_reject_after_needs_review(tmp_path: Path) -> None:
    from triage import seeds, verifier
    from triage.status import TransitionConflict

    db_path = tmp_path / "triage.db"
    db.init_schema(db_path)
    seed = next(s for s in seeds.load_known() if s.expected == "true_positive")
    verdict = _tp_verdict("tmp")
    with db.session(db_path) as conn:
        fid = seeds.insert_seed(conn, seed)
        verdict["finding_id"] = fid
        envelope = {"pass1": verdict, "pass2": verdict, "consolidated": verdict}
        conn.execute(
            "UPDATE findings SET status = 'verifying', verdict_json = ? WHERE id = ?",
            (json.dumps(envelope), fid),
        )

    real = verifier._run_harness

    def flip_then_run(command: str, worktree: Path):
        with db.session(db_path) as conn:
            conn.execute("UPDATE findings SET status = 'needs_review' WHERE id = ?", (fid,))
        return real(command, worktree)

    verifier._run_harness = flip_then_run  # type: ignore[method-assign]
    try:
        try:
            verifier.verify_finding(fid, db_path, worktree=REPO_ROOT / seed.worktree)
        except TransitionConflict:
            pass
        else:
            raise AssertionError("overlapping verify should conflict")
    finally:
        verifier._run_harness = real  # type: ignore[method-assign]

    with db.session(db_path) as conn:
        status = conn.execute("SELECT status FROM findings WHERE id = ?", (fid,)).fetchone()["status"]
    assert status == "needs_review"
