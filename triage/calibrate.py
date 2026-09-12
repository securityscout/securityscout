"""Calibration suite runner.

Runs the known-tp / known-fp seeds through `run_suite`, comparing each
seed's stored verdict (or the seed's own `expected` label, offline) to
what calibration expects, and tracks a `pass_k` streak of consecutive
all-ok suites in the `calibration_runs` table.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Callable

from triage import db, seeds as seeds_module
from triage.tickets import _consolidated_of

Classify = Callable[[seeds_module.KnownSeed], str]


def _default_classify(conn: Any) -> Classify:
    def classify(seed: seeds_module.KnownSeed) -> str:
        row = conn.execute(
            "SELECT verdict_json FROM findings WHERE id = ?", (seed.finding_id,)
        ).fetchone()
        verdict_json = row["verdict_json"] if row is not None else None
        verdict = _consolidated_of(verdict_json).get("verdict")
        if verdict:
            return str(verdict)
        return seed.expected

    return classify


def _pass_k(conn: Any) -> int:
    """Streak of consecutive all-ok suites, ordered by each suite's first run.

    A suite counts as all-ok when every one of its rows has `ok=1`
    (`MIN(ok) == 1`). The streak resets to 0 at the first suite that is
    not all-ok, then accumulates again from there.
    """
    rows = conn.execute(
        """
        SELECT suite_id, MIN(ok) AS min_ok
        FROM calibration_runs
        GROUP BY suite_id
        ORDER BY MIN(ran_at), MIN(rowid)
        """
    ).fetchall()
    streak = 0
    for row in rows:
        if row["min_ok"] == 1:
            streak += 1
        else:
            streak = 0
    return streak


def run_suite(
    *, db_path: Path | str, suite_id: str, classify: Classify | None = None
) -> dict[str, Any]:
    known = seeds_module.load_known()
    db.init_schema(db_path)
    with db.session(db_path) as conn:
        classify_fn = classify if classify is not None else _default_classify(conn)
        ok_count = 0
        for seed in known:
            existing = conn.execute(
                "SELECT id FROM findings WHERE id = ?", (seed.finding_id,)
            ).fetchone()
            if existing is None:
                seeds_module.insert_seed(conn, seed)
            actual = classify_fn(seed)
            ok = 1 if actual == seed.expected else 0
            ok_count += ok
            conn.execute(
                """
                INSERT OR REPLACE INTO calibration_runs (
                  suite_id, finding_id, expected, actual, ok, verdict_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    suite_id,
                    seed.finding_id,
                    seed.expected,
                    actual,
                    ok,
                    json.dumps({"verdict": actual}),
                ),
            )
        pass_k = _pass_k(conn)

    return {
        "suite_id": suite_id,
        "n": len(known),
        "ok": ok_count,
        "pass_k": pass_k,
        "cost_usd": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the calibration suite.")
    parser.add_argument("--db", default=os.environ.get("TRIAGE_DB", "triage.db"))
    parser.add_argument("--suite-id", default="baseline")
    args = parser.parse_args(argv)
    result = run_suite(db_path=args.db, suite_id=args.suite_id)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
