"""Post-verdict PoC replay + sanitizer-claim grep.

Three independent checks per verdict:
  1. Schema validation against `data/verdict.schema.json` (deterministic).
  2. PoC replay: re-run `poc.command` from a fresh subprocess; demand the
     exit_code matches; 90s timeout.
  3. Sanitizer-claim grep: every entry in `sanitizers_in_path` must be
     findable at the cited file:line via `rg --fixed-strings`. Misses →
     demote verdict with `hallucinated_sanitizer`.

Not yet implemented.
"""

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    raise SystemExit("triage.verifier is not yet implemented.")


if __name__ == "__main__":  # pragma: no cover
    main()
