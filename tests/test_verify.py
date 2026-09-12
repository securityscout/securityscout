"""Bootstrap gate — contracts that do not spawn cursor-agent."""

from __future__ import annotations

import inspect

from triage import verify
from triage.config import CONFIG


def test_smoke_uses_config_model_recon() -> None:
    source = inspect.getsource(verify.check_cursor_agent_smoke)
    assert "composer-2.5-fast" not in source
    assert "CONFIG.model_recon" in source
    assert CONFIG.model_recon


def test_verify_module_has_no_hardcoded_composer_slug() -> None:
    source = inspect.getsource(verify)
    assert "composer-2.5-fast" not in source
