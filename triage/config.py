"""Runtime configuration: env loading, model slugs, budget guardrails.

Loads `.env`. Model slugs are env-driven — never hardcoded — so the
orchestrator picks up whatever the user's Cursor plan currently exposes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is in pyproject.toml but might not be in PYTHONPATH yet
    load_dotenv = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_NAME = "sast-triage"


def _load_env_once() -> None:
    if load_dotenv is None:
        return
    env_path = REPO_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=False)


_load_env_once()


@dataclass(frozen=True)
class TriageConfig:
    """Single source of truth for runtime settings."""

    db_path: Path = field(default_factory=lambda: Path(os.getenv("TRIAGE_DB_PATH", "triage.db")))
    concurrency: int = field(default_factory=lambda: int(os.getenv("TRIAGE_CONCURRENCY", "4")))

    # Two-pass models chosen to be genuinely different so pass1 and pass2 are
    # not correlated (the argue_tp / argue_fp postures must steelman opposite
    # null hypotheses without sharing a model's blind spots).
    model_pass1: str = field(default_factory=lambda: os.getenv(
        "TRIAGE_MODEL_PASS1", "claude-opus-4-7-thinking-xhigh"))
    model_pass2: str = field(default_factory=lambda: os.getenv(
        "TRIAGE_MODEL_PASS2", "claude-4.6-opus-high-thinking"))
    model_recon: str = field(default_factory=lambda: os.getenv(
        "TRIAGE_MODEL_RECON", "claude-opus-4-7-thinking-high"))

    # Per-finding ceiling intentionally equals the monthly cap. A single
    # finding may consume the whole budget if a deep multi-pass investigation
    # is warranted; the monthly aggregate is the real guard.
    budget_usd_monthly: float = field(default_factory=lambda: float(os.getenv("BUDGET_USD", "200")))
    per_finding_usd_ceiling: float = field(default_factory=lambda: float(
        os.getenv("PER_FINDING_USD_CEILING", "200")))

    # Every git-touching component must honor this. Target repos are
    # cloneable but never written to.
    readonly_target_repos: bool = field(default_factory=lambda: os.getenv(
        "TRIAGE_READONLY_TARGET_REPOS", "1") not in ("0", "false", "False", ""))


CONFIG = TriageConfig()

__all__ = [
    "CONFIG",
    "REPO_ROOT",
    "SKILL_NAME",
    "TriageConfig",
]
