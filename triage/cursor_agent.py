"""cursor-agent spawn.

cursor-agent (2026.01.23-916f423) hangs on stdin even with `--print`
unless stdin is closed; every spawn must pass `stdin=subprocess.DEVNULL`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def parse_agent_json(stdout: str) -> dict:
    parsed = json.loads(stdout.strip())
    if not isinstance(parsed, dict):
        raise ValueError(f"agent stdout is {type(parsed).__name__}, expected object")
    result = parsed.get("result")
    if isinstance(result, str) and result.strip():
        inner = json.loads(result)
        if not isinstance(inner, dict):
            raise ValueError("agent result JSON is not an object")
        return inner
    if isinstance(result, dict):
        return result
    return parsed


def spawn_cursor_agent(
    *,
    prompt: str,
    model: str,
    cwd: Path,
    mode: str | None = None,
    timeout: int = 600,
) -> dict:
    binary = shutil.which("cursor-agent")
    if not binary:
        raise RuntimeError("cursor-agent not on PATH")
    cmd = [binary, "--print", "--output-format", "json", "--model", model]
    if mode:
        cmd.extend(["--mode", mode])
    # -p is the only headless prompt channel; stdin must stay DEVNULL
    # or this binary hangs, so the prompt is visible in ps.
    cmd.extend(["-p", prompt])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"cursor-agent timed out after {timeout}s") from e
    except OSError as e:
        raise RuntimeError(f"cursor-agent spawn failed: {e}") from e
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()[:400]
        raise RuntimeError(f"cursor-agent exited {proc.returncode}: {err}")
    if not proc.stdout.strip():
        raise RuntimeError("cursor-agent produced empty stdout")
    try:
        return parse_agent_json(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"cursor-agent stdout is not JSON: {e}") from e
