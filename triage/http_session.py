"""Persistent HTTP capture for hunt-mode http_replay proofs.

A hunt specialist replays through `gateway_execute` so the bytes
`gateway.invoke` hashes into `tool_spans.result_sha256` are exactly the
transcript bytes written to disk — one serialization path, not two that
could drift apart.
"""

from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path
from typing import Any, Callable

import httpx

from triage.gateway import canonical_json_bytes

_BODY_EXCERPT_CAP = 2000

_LOCK = threading.Lock()
_SESSIONS: dict[str, httpx.Client] = {}


def get_session(run_id: str, *, transport: httpx.BaseTransport | None = None) -> httpx.Client:
    """Return the persistent client for `run_id`, creating one on first use.

    `transport` only takes effect on the first call for a given run_id;
    later calls return the cached client and ignore it.
    """
    with _LOCK:
        client = _SESSIONS.get(run_id)
        if client is None:
            client = httpx.Client(transport=transport)
            _SESSIONS[run_id] = client
        return client


def close_session(run_id: str) -> None:
    with _LOCK:
        client = _SESSIONS.pop(run_id, None)
    if client is not None:
        client.close()


def capture_http(run_id: str, method: str, url: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Send one request through the run's persistent session as a transcript.

    The transcript is self-contained (request, response, status, body
    excerpt, timing) so the verifier can hash-check it offline later
    without re-hitting the host.
    """
    client = get_session(run_id)
    start = time.monotonic()
    response = client.request(method, url, timeout=timeout)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    return {
        "request": {"method": method.upper(), "url": url},
        "response": {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body_excerpt": response.text[:_BODY_EXCERPT_CAP],
        },
        "timing_ms": elapsed_ms,
    }


def gateway_execute(run_id: str, transcripts_dir: Path | str) -> Callable[[dict[str, Any]], bytes]:
    """Build an `execute` for `gateway.invoke` that captures + persists a transcript.

    The returned bytes are the same bytes written to
    `transcripts_dir/<sha256>.json`, so `gateway.invoke`'s own
    `result_sha256` already is that artifact's hash.
    """
    out_dir = Path(transcripts_dir)

    def _execute(args: dict[str, Any]) -> bytes:
        transcript = capture_http(run_id, str(args["method"]), str(args["url"]))
        body = canonical_json_bytes(transcript)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{hashlib.sha256(body).hexdigest()}.json").write_bytes(body)
        return body

    return _execute
