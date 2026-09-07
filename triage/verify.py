"""Bootstrap acceptance gate.

Verifies the local toolchain is ready before the orchestrator spawns any
agents. Exits 0 only if every required check passes.

Required (failure = exit 1):
  - `cursor-agent` on PATH and reports a version
  - `cursor-agent --print --output-format json -p "say hi"` works headless
  - SQLite schema present in $TRIAGE_DB_PATH and contains the required tables
  - `sast-triage` skill installed at ~/.cursor/skills/sast-triage/SKILL.md
  - Python deps importable: jsonschema, dotenv
  - data/verdict.schema.json present and parses as JSON Schema 2020-12

Strongly recommended (failure = warn, but exit 0):
  - `gh` on PATH (org inventory / clone)

Run as:
    python -m triage.verify
or:
    make verify
"""

from __future__ import annotations

import importlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from triage.config import CONFIG, REPO_ROOT, SKILL_NAME
from triage.db import list_tables


GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
RESET = "\033[0m"


def _ok(msg: str) -> None:
    print(f"{GREEN}✓{RESET} {msg}")


def _fail(msg: str) -> None:
    print(f"{RED}✗{RESET} {msg}")


def _warn(msg: str) -> None:
    print(f"{YELLOW}!{RESET} {msg}")


# Soft checks — warn, do not fail the gate.
# `gh` is the inventory / clone path. `glab` is only for gitlab.com hosts.
RECOMMENDED_TOOLS = ["gh"]
OPTIONAL_TOOLS = ["glab"]
REQUIRED_PYTHON_MODULES = ["jsonschema", "dotenv"]
REQUIRED_TABLES = {"findings", "repo_recon", "calibration_runs"}
SKILL_PATH = Path.home() / ".cursor" / "skills" / SKILL_NAME / "SKILL.md"
VERDICT_SCHEMA_PATH = REPO_ROOT / "data" / "verdict.schema.json"


def check_cursor_agent() -> bool:
    binary = shutil.which("cursor-agent")
    if not binary:
        _fail("cursor-agent not on PATH (install per https://docs.cursor.com/cli)")
        return False
    try:
        ver = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=10, check=False
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        _fail(f"cursor-agent --version raised {type(e).__name__}: {e}")
        return False
    if ver.returncode != 0:
        _fail(f"cursor-agent --version exited {ver.returncode}: {ver.stderr.strip()}")
        return False
    _ok(f"cursor-agent installed: {binary} ({ver.stdout.strip().splitlines()[-1]})")
    return True


def check_cursor_agent_smoke() -> bool:
    """Confirm `cursor-agent --print --output-format json` works headless.

    cursor-agent (2026.01.23-916f423) hangs on stdin even with `--print`
    unless stdin is closed; every orchestrator spawn must pass
    `stdin=subprocess.DEVNULL`.
    """
    binary = shutil.which("cursor-agent")
    if not binary:
        return False
    try:
        proc = subprocess.run(
            [binary, "--print", "--output-format", "json",
             "--model", "composer-2.5-fast",
             "-p", "say hi"],
            capture_output=True, text=True, timeout=90, check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        _fail("cursor-agent smoke test timed out after 90s")
        return False
    except OSError as e:
        _fail(f"cursor-agent smoke test raised {type(e).__name__}: {e}")
        return False
    if proc.returncode != 0:
        _fail(f"cursor-agent smoke test exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return False
    out = proc.stdout.strip()
    if not out:
        _fail("cursor-agent smoke test produced empty stdout")
        return False
    try:
        parsed = json.loads(out)
    except json.JSONDecodeError as e:
        _fail(f"cursor-agent smoke test stdout is not valid JSON ({e}). First 200 chars: {out[:200]!r}")
        return False
    if not isinstance(parsed, dict):
        _fail(f"cursor-agent envelope is {type(parsed).__name__}, expected dict")
        return False
    if parsed.get("is_error", False):
        _fail(f"cursor-agent smoke returned is_error=true: {parsed.get('result', '')[:300]}")
        return False
    dur = parsed.get("duration_ms", "?")
    _ok(f"cursor-agent --print --output-format json works headless ({dur} ms)")
    return True


def check_schema() -> bool:
    db_path = CONFIG.db_path
    if not Path(db_path).exists():
        _fail(f"SQLite DB not found at {db_path} — run `make schema`")
        return False
    try:
        objects = set(list_tables(db_path))
    except Exception as e:  # noqa: BLE001
        _fail(f"could not list tables in {db_path}: {e}")
        return False
    missing = REQUIRED_TABLES - objects
    if missing:
        _fail(f"DB at {db_path} is missing tables: {sorted(missing)}")
        return False
    _ok(f"SQLite schema at {db_path} has all required tables")
    return True


def check_skill() -> bool:
    if not SKILL_PATH.exists():
        _fail(f"{SKILL_NAME} skill not installed at {SKILL_PATH} — run `make skill`")
        return False
    body = SKILL_PATH.read_text(encoding="utf-8", errors="replace")
    if f"name: {SKILL_NAME}" not in body or "SAST Finding Triage" not in body:
        _fail(f"{SKILL_PATH} exists but doesn't look like the {SKILL_NAME} skill")
        return False
    _ok(f"{SKILL_NAME} skill installed at {SKILL_PATH} ({len(body)} bytes)")
    return True


def check_verdict_schema() -> bool:
    if not VERDICT_SCHEMA_PATH.exists():
        _fail(f"verdict schema missing at {VERDICT_SCHEMA_PATH}")
        return False
    try:
        schema = json.loads(VERDICT_SCHEMA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        _fail(f"{VERDICT_SCHEMA_PATH} is not valid JSON: {e}")
        return False
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        _fail(f"{VERDICT_SCHEMA_PATH} is not declared as draft 2020-12")
        return False
    try:
        from jsonschema import Draft202012Validator
        Draft202012Validator.check_schema(schema)
    except Exception as e:  # noqa: BLE001
        _fail(f"verdict schema fails Draft202012Validator.check_schema: {e}")
        return False
    _ok(f"verdict schema at {VERDICT_SCHEMA_PATH} is valid draft 2020-12")
    return True


def check_python_modules() -> bool:
    all_ok = True
    for mod in REQUIRED_PYTHON_MODULES:
        try:
            importlib.import_module(mod)
        except ImportError as e:
            _fail(f"python module not importable: {mod} ({e})")
            all_ok = False
    if all_ok:
        _ok(f"python deps importable: {', '.join(REQUIRED_PYTHON_MODULES)}")
    return all_ok


def check_brew_tools() -> bool:
    """Soft check — warns but does not fail the gate."""
    all_ok = True
    for tool in RECOMMENDED_TOOLS:
        if shutil.which(tool):
            _ok(f"{tool} installed: {shutil.which(tool)}")
        else:
            _warn(f"{tool} MISSING (needed once recon comes online)")
            all_ok = False
    for tool in OPTIONAL_TOOLS:
        if shutil.which(tool):
            _ok(f"{tool} installed: {shutil.which(tool)} (optional — Java one-file PoCs)")
        else:
            print(f"{DIM}  {tool} not installed (OPTIONAL — gitlab.com access probe).{RESET}")
    return all_ok


def main(argv: list[str] | None = None) -> int:
    print(f"{DIM}securityscout — bootstrap acceptance gate{RESET}")
    print(f"{DIM}repo root: {REPO_ROOT}{RESET}")
    print()

    print("== Required checks ==")
    required = [
        check_cursor_agent(),
        check_python_modules(),
        check_verdict_schema(),
        check_schema(),
        check_skill(),
        check_cursor_agent_smoke(),
    ]

    print()
    print("== Recommended (warnings only) ==")
    check_brew_tools()

    print()
    if all(required):
        print(f"{GREEN}PASS{RESET} — bootstrap acceptance gate cleared.")
        return 0

    failed = sum(1 for r in required if not r)
    print(f"{RED}FAIL{RESET} — {failed} required check(s) failed.")
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
