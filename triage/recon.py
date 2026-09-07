"""Per-(repo, SHA) recon agent.

Recon is one-time per repo+SHA, cached at `.cache/recon/<slug>-<sha>.json`
and in the `repo_recon` table. Uses `cursor-agent --mode plan` for
read-only exploration of the target repo's attack surface.

Not yet implemented.
"""

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    raise SystemExit("triage.recon is not yet implemented.")


if __name__ == "__main__":  # pragma: no cover
    main()
