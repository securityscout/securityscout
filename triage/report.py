"""Per-TP markdown writeup generation.

Produces `findings/<finding-id>-<slug>.md` for every verdict whose
`verdict` starts with `true_positive`. False positives do not get a
markdown writeup — the verdict JSON is the artifact.

Not yet implemented.
"""

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    raise SystemExit("triage.report is not yet implemented.")


if __name__ == "__main__":  # pragma: no cover
    main()
