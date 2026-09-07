"""Calibration suite runner.

Runs `data/known-tp.jsonl` + `data/known-fp.jsonl` through the full
pipeline and compares the orchestrator's verdicts to the known-good
labels. Persists results to the `calibration_runs` table for trend
analysis across model / prompt revisions.

Not yet implemented.
"""

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    raise SystemExit("triage.calibrate is not yet implemented.")


if __name__ == "__main__":  # pragma: no cover
    main()
