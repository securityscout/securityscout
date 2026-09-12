"""Acceptance tests for the calibration suite runner.

Offline: `classify` is injected so no model is ever spawned.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage import calibrate, db, seeds


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    p = tmp_path / "calibrate-test.db"
    db.init_schema(p)
    return p


def _classify_matching_expected(seed: seeds.KnownSeed) -> str:
    return seed.expected


def _classify_flip_one(flipped_rule_id: str):
    def classify(seed: seeds.KnownSeed) -> str:
        if seed.rule_id == flipped_rule_id:
            return "indeterminate"
        return seed.expected

    return classify


def test_suite_writes_tp_and_fp_rows(db_path: Path) -> None:
    result = calibrate.run_suite(
        db_path=db_path, suite_id="s1", classify=_classify_matching_expected
    )

    assert result["n"] == 2
    assert result["ok"] == result["n"]
    assert result["pass_k"] == 1
    assert result["cost_usd"] == 0

    with db.session(db_path) as conn:
        rows = conn.execute(
            "SELECT expected, actual, ok FROM calibration_runs WHERE suite_id = 's1'"
        ).fetchall()
    assert len(rows) == 2
    assert {r["expected"] for r in rows} == {"true_positive", "false_positive"}
    assert all(r["ok"] == 1 for r in rows)


def test_second_all_ok_suite_increments_pass_k(db_path: Path) -> None:
    calibrate.run_suite(db_path=db_path, suite_id="s1", classify=_classify_matching_expected)
    result = calibrate.run_suite(
        db_path=db_path, suite_id="s2", classify=_classify_matching_expected
    )

    assert result["pass_k"] == 2


def test_failed_suite_resets_pass_k(db_path: Path) -> None:
    known = seeds.load_known()
    fp_rule_id = next(s.rule_id for s in known if s.expected == "false_positive")

    first = calibrate.run_suite(
        db_path=db_path, suite_id="s1", classify=_classify_matching_expected
    )
    assert first["pass_k"] == 1

    second = calibrate.run_suite(
        db_path=db_path, suite_id="s2", classify=_classify_flip_one(fp_rule_id)
    )

    assert second["pass_k"] == 0


def _write_consolidated_verdict(db_path: Path, finding_id: str, verdict: str) -> None:
    envelope = json.dumps({"pass1": {}, "pass2": {}, "consolidated": {"verdict": verdict}})
    with db.session(db_path) as conn:
        conn.execute(
            "UPDATE findings SET verdict_json = ? WHERE id = ?", (envelope, finding_id)
        )


def test_default_classify_reads_the_consolidated_verdict(db_path: Path) -> None:
    tp_seed = next(s for s in seeds.load_known() if s.expected == "true_positive")
    with db.session(db_path) as conn:
        seeds.insert_seed(conn, tp_seed)
    _write_consolidated_verdict(db_path, tp_seed.finding_id, "true_positive")

    calibrate.run_suite(db_path=db_path, suite_id="s1")

    with db.session(db_path) as conn:
        row = conn.execute(
            "SELECT actual, ok FROM calibration_runs WHERE suite_id = 's1' AND finding_id = ?",
            (tp_seed.finding_id,),
        ).fetchone()
    assert row["actual"] == "true_positive"
    assert row["ok"] == 1


def test_default_classify_flags_a_mismatched_consolidated_verdict(db_path: Path) -> None:
    """A real worker run that disagrees with the seed label must not read as ok=1.

    The verdict lives at `verdict_json.consolidated.verdict`, not a top-level
    `verdict` key — a classifier that misses the envelope would always fall
    back to the seed's own `expected` and silently report every suite as
    fully passing.
    """
    tp_seed = next(s for s in seeds.load_known() if s.expected == "true_positive")
    with db.session(db_path) as conn:
        seeds.insert_seed(conn, tp_seed)
    _write_consolidated_verdict(db_path, tp_seed.finding_id, "false_positive")

    result = calibrate.run_suite(db_path=db_path, suite_id="s1")

    with db.session(db_path) as conn:
        row = conn.execute(
            "SELECT actual, ok FROM calibration_runs WHERE suite_id = 's1' AND finding_id = ?",
            (tp_seed.finding_id,),
        ).fetchone()
    assert row["actual"] == "false_positive"
    assert row["ok"] == 0
    assert result["pass_k"] == 0
