"""Tool gateway: scope + blast-radius enforcement, hashed evidence, kill.

`scope` and `blast_radius` are immutable run inputs read from the `runs`
row; a caller cannot override them through `invoke` kwargs.

Both checks fail closed on bad data rather than degrading to permissive:
an empty or malformed `scope.hosts` denies every host, and a tier outside
`BLAST_RADIUS` restricts as `safe`.
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


def _scope_hosts(scope_json: str | None) -> set[str]:
    """Lowercased hostnames in scope.

    Every malformed shape — unparseable JSON, a non-object, a null or
    non-list `hosts` — yields the empty set, which denies every host. A
    scope this broken cannot be honoured, and guessing wider than the
    operator wrote is the one failure mode worth ruling out.
    """
    try:
        scope = json.loads(scope_json or "{}")
    except ValueError:
        return set()
    if not isinstance(scope, dict):
        return set()
    hosts = scope.get("hosts")
    if not isinstance(hosts, (list, tuple)):
        return set()
    return {str(h).lower() for h in hosts}


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


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding shared by every hash site.

    `args_hash` here and the transcript hash in `http_session.gateway_execute`
    must agree on separators/key order, or independently computed hashes for
    the same logical payload would silently diverge.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


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

    if not args.get("method"):
        raise ValueError("args['method'] is required")
    method = str(args["method"]).upper()
    host = (urlparse(str(args.get("url", ""))).hostname or "").lower()

    if host not in _scope_hosts(row["scope_json"]):
        raise OutOfScopeError(host=host)

    # Membership, not equality against 'safe': an unrecognized or miscased
    # tier restricts as `safe`. A control that disables itself on a
    # malformed row is worse than one that over-refuses a legitimate call.
    raw_tier = row["blast_radius"]
    tier = raw_tier if raw_tier in BLAST_RADIUS else "safe"
    if tier == "safe" and method not in SAFE_METHODS:
        raise BlastRadiusError(method=method, blast_radius=raw_tier)

    call_id = uuid.uuid4().hex
    event = threading.Event()
    with _LOCK:
        _IN_FLIGHT[call_id] = event

    try:
        result = execute(args)
        if event.is_set():
            raise GatewayCancelled(call_id)

        args_hash = hashlib.sha256(canonical_json_bytes(args)).hexdigest()
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
