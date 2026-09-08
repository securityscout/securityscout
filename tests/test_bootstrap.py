"""bootstrap-pip installs the project extra."""

from __future__ import annotations

import re
from triage.config import REPO_ROOT


def _makefile() -> str:
    return (REPO_ROOT / "Makefile").read_text(encoding="utf-8")


def _bootstrap_pip_recipe() -> str:
    text = _makefile()
    match = re.search(
        r"^bootstrap-pip:.*?(?=^\S|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, "bootstrap-pip target missing"
    return match.group(0)


def _pyproject() -> str:
    return (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_bootstrap_pip_installs_editable_dev() -> None:
    recipe = _bootstrap_pip_recipe()
    assert 'install -e "$(MAKEFILE_DIR)[dev]"' in recipe
    assert "jsonschema" not in recipe
    assert "$(CURDIR)[dev]" not in recipe
    assert "firstword $(MAKEFILE_LIST)" in _makefile()


def test_dev_extra_declares_httpx() -> None:
    text = _pyproject()
    block = re.search(
        r"\[project\.optional-dependencies\]\s*\ndev\s*=\s*\[(.*?)\]",
        text,
        flags=re.DOTALL,
    )
    assert block is not None, "dev extra missing"
    extra = block.group(1)
    assert re.search(r'"httpx>=0\.28"', extra)


def test_serve_declares_uvicorn() -> None:
    assert re.search(r"^serve:", _makefile(), flags=re.MULTILINE)
    block = re.search(
        r"^dependencies\s*=\s*\[(.*?)\]",
        _pyproject(),
        flags=re.MULTILINE | re.DOTALL,
    )
    assert block is not None, "[project] dependencies missing"
    assert "uvicorn" in block.group(1)
