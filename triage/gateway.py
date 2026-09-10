"""Tool gateway: scope + blast-radius enforcement, hashed evidence, kill.

`scope` and `blast_radius` are immutable run inputs read from the `runs`
row; a caller cannot override them through `invoke` kwargs. An empty
`scope.hosts` list is fail-closed — every host is denied.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from triage import db

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
BLAST_RADIUS = ("safe", "intrusive", "destructive")


class OutOfScopeError(Exception):
    def __init__(self, host: str) -> None:
        self.host = host
        super().__init__(f"host not in scope: {host}")


class BlastRadiusError(Exception):
    def __init__(self, method: str, blast_radius: str) -> None:
        self.method = method
        self.blast_radius = blast_radius
        super().__init__(f"{method} not allowed at blast_radius={blast_radius}")


class GatewayCancelled(Exception):
    def __init__(self, call_id: str) -> None:
        self.call_id = call_id
        super().__init__(f"call {call_id} was killed")


_LOCK = threading.Lock()
_IN_FLIGHT: dict[str, threading.Event] = {}


def in_flight_ids() -> list[str]:
    with _LOCK:
        return list(_IN_FLIGHT.keys())


def invoke(
    run_id: str,
    tool: str,
    args: dict[str, Any],
    *,
    db_path: Path | str | None = None,
    agent: str = "test",
    execute: Callable[[dict[str, Any]], bytes] | None = None,
) -> dict[str, Any]:
    if execute is None:
        raise RuntimeError("execute is required")

    with db.session(db_path) as conn:
        row = conn.execute("SELECT scope_json, blast_radius FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        raise LookupError(run_id)

    scope = json.loads(row["scope_json"] or "{}")
    hosts = {h.lower() for h in scope.get("hosts", [])}
    method = str(args.get("method", "GET")).upper()
    url = str(args.get("url", ""))
    host = (urlparse(url).hostname or "").lower()

    if host not in hosts:
        raise OutOfScopeError(host=host)

    blast_radius = row["blast_radius"]
    if blast_radius == "safe" and method not in SAFE_METHODS:
        raise BlastRadiusError(method=method, blast_radius=blast_radius)

    call_id = uuid.uuid4().hex
    event = threading.Event()
    with _LOCK:
        _IN_FLIGHT[call_id] = event

    try:
        result = execute(args)
        if event.is_set():
            raise GatewayCancelled(call_id)

        args_hash = hashlib.sha256(
            json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        result_sha256 = hashlib.sha256(result).hexdigest()
        t = datetime.now(timezone.utc).isoformat()

        with db.session(db_path) as conn:
            conn.execute(
                "INSERT INTO tool_spans (id, run_id, agent, tool, args_hash, result_sha256, t) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (call_id, run_id, agent, tool, args_hash, result_sha256, t),
            )

        return {
            "id": call_id,
            "run_id": run_id,
            "agent": agent,
            "tool": tool,
            "args_hash": args_hash,
            "result_sha256": result_sha256,
            "t": t,
        }
    finally:
        with _LOCK:
            _IN_FLIGHT.pop(call_id, None)


def kill(call_id: str) -> None:
    with _LOCK:
        event = _IN_FLIGHT.get(call_id)
    if event is None:
        raise LookupError(call_id)
    event.set()
