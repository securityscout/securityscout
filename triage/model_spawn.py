"""Prompt-in / JSON-out model spawn. No vendor tools, MCP, or sandbox."""

from __future__ import annotations

import json
import os
from pathlib import Path

from triage.cursor_agent import spawn_cursor_agent

_BACKENDS = ("anthropic", "openai", "cursor")
_JSON_ONLY = "Reply with a single JSON object only."
_VENDOR_TIMEOUT = 600
_MAX_TOKENS = 8192


def _backend() -> str:
    raw = os.environ.get("TRIAGE_MODEL_BACKEND")
    if raw is None or not str(raw).strip():
        raise RuntimeError(
            "TRIAGE_MODEL_BACKEND is unset. Set it to anthropic, openai, or cursor."
        )
    value = str(raw).strip().lower()
    if value not in _BACKENDS:
        raise RuntimeError(
            f"TRIAGE_MODEL_BACKEND={raw!r} is not supported. Use anthropic, openai, or cursor."
        )
    return value


def _anthropic_client():
    from anthropic import Anthropic

    return Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))


def _openai_client():
    from openai import OpenAI

    return OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


def _strip_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _parse_json_object(text: str) -> dict:
    try:
        parsed = json.loads(_strip_fence(text))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"model output is not JSON: {e}") from e
    if not isinstance(parsed, dict):
        raise ValueError(f"model output is {type(parsed).__name__}, expected object")
    return parsed


def _anthropic_text(message) -> str:
    parts: list[str] = []
    for block in message.content:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "".join(parts)


def _complete_anthropic(prompt: str, model: str) -> dict:
    try:
        message = _anthropic_client().messages.create(
            model=model,
            max_tokens=_MAX_TOKENS,
            system=_JSON_ONLY,
            messages=[{"role": "user", "content": prompt}],
            timeout=_VENDOR_TIMEOUT,
        )
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"anthropic messages.create failed: {e}") from e
    text = _anthropic_text(message)
    if not text.strip():
        raise RuntimeError("anthropic produced empty text")
    return _parse_json_object(text)


def _complete_openai(prompt: str, model: str) -> dict:
    try:
        response = _openai_client().responses.create(
            model=model,
            input=prompt,
            instructions=_JSON_ONLY,
            text={"format": {"type": "json_object"}},
            store=False,
            timeout=_VENDOR_TIMEOUT,
        )
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"openai responses.create failed: {e}") from e
    text = getattr(response, "output_text", None) or ""
    if not str(text).strip():
        raise RuntimeError("openai produced empty text")
    return _parse_json_object(str(text))


def complete(
    prompt: str,
    model: str,
    *,
    cwd: Path | None = None,
    mode: str | None = None,
) -> dict:
    backend = _backend()
    if backend == "cursor":
        if cwd is None:
            raise RuntimeError("cursor backend requires cwd")
        return spawn_cursor_agent(prompt=prompt, model=model, cwd=cwd, mode=mode)
    if backend == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        return _complete_anthropic(prompt, model)
    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")
    return _complete_openai(prompt, model)


def spawn(ctx) -> dict:
    return complete(ctx.prompt, ctx.model, cwd=getattr(ctx, "worktree", None))
