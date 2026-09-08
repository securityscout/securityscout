"""Makefile recipe contracts: install, serve, and flags that reach argv."""

from __future__ import annotations

import re
import subprocess

from triage.config import REPO_ROOT


def _makefile() -> str:
    return (REPO_ROOT / "Makefile").read_text(encoding="utf-8")


def _recipe(target: str) -> str:
    """The target's own body — usage comments and `help` echoes sit outside."""
    match = re.search(
        rf"^{re.escape(target)}:.*?(?=^\S|\Z)",
        _makefile(),
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"{target} target missing"
    return match.group(0)


def _make_n(*args: str) -> str:
    proc = subprocess.run(
        ["make", "-n", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _pyproject() -> str:
    return (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_bootstrap_pip_installs_editable_dev() -> None:
    recipe = _recipe("bootstrap-pip")
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


def test_recipes_do_not_quote_make_vars_into_argv() -> None:
    ingest = _recipe("ingest")
    classify = _recipe("classify-access")

    for leak in ("'$(EXCLUDE)'", "'$(HOSTS)'", "'$(PROBE)'"):
        assert leak not in ingest + classify

    assert "--hosts" not in classify
    assert "--probe" not in classify
    assert "flags=" not in ingest
    assert "flags=" not in classify


def test_recipe_values_survive_an_embedded_double_quote() -> None:
    out = _make_n("ingest", "CSV=data/csv/x.csv", 'EXCLUDE=*a"b*')
    assert r'--exclude-repos "*a\"b*"' in out

    out = _make_n("classify-access", 'HOSTS=a"b.com')
    assert r'TRIAGE_ACCESS_HOSTS="a\"b.com"' in out


def test_classify_access_probe_becomes_env_prefix() -> None:
    out = _make_n("classify-access", "PROBE=membership")

    assert "TRIAGE_ACCESS_PROBE=membership" in out.replace('"', "")
    assert "--probe" not in out
    assert "'membership'" not in out


def test_classify_access_hosts_become_env_prefix() -> None:
    out = _make_n("classify-access", "HOSTS=github.com,gitlab.com")

    assert "TRIAGE_ACCESS_HOSTS=github.com,gitlab.com" in out.replace('"', "")
    assert "--hosts" not in out
    assert "'github.com" not in out


def test_classify_access_without_overrides_sets_no_env() -> None:
    out = _make_n("classify-access")

    # An empty TRIAGE_ACCESS_HOSTS is not "no override": hosts_to_check()
    # reads it as zero hosts and every repo classifies no_access.
    assert "TRIAGE_ACCESS_HOSTS=" not in out
    assert "TRIAGE_ACCESS_PROBE=" not in out


def test_classify_access_commit_still_applies() -> None:
    out = _make_n("classify-access", "COMMIT=1")

    assert "--apply" in out
    assert "-m triage.classify_access" in out
    assert "--db" in out


def test_ingest_exclude_is_its_own_quoted_argv() -> None:
    out = _make_n("ingest", "CSV=data/csv/x.csv", "EXCLUDE=*foo*,*bar*")

    assert '--exclude-repos "*foo*,*bar*"' in out
    assert "--exclude-repos '*foo*" not in out
    for line in out.splitlines():
        if "flags=" in line:
            assert "--exclude-repos" not in line


def test_ingest_without_exclude_passes_no_flag() -> None:
    out = _make_n("ingest", "CSV=data/csv/x.csv")

    assert "--exclude-repos" not in out


def test_ingest_valueless_flags_survive() -> None:
    out = _make_n(
        "ingest", "CSV=data/csv/x.csv", "DRY=1", "NO_DEFAULT_EXCLUDES=1"
    )

    assert "--dry-run" in out
    assert "--no-default-excludes" in out
    assert "-m triage.ingest" in out
    assert '--csv "data/csv/x.csv"' in out
    assert "--db" in out
