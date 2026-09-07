"""Two-pass triage worker.

For each leased finding row:
  1. Anchor: confirm repo+SHA+file+line still match the scanner's view.
  2. Pass 1 (argue_tp): cursor agent with model_pass1.
  3. Pass 2 (argue_fp): cursor agent with model_pass2 (different model).
  4. Consolidate the two verdicts.
  5. Store all three (pass1, pass2, consolidated) in `findings.verdict_json`
     and the raw `verdicts/<id>-pass{1,2}.json` files.

Not yet implemented.
"""

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    raise SystemExit("triage.triage_worker is not yet implemented.")


if __name__ == "__main__":  # pragma: no cover
    main()
