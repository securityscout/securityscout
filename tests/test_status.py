"""Finding-status transition helper."""

from __future__ import annotations

import pytest


def test_rejects_done_to_published() -> None:
    from triage.status import IllegalTransition, apply_transition

    with pytest.raises(IllegalTransition):
        apply_transition("done", "published")
