"""Finding-status transitions.

excluded has no outgoing edges; un-exclude is an operator action
not represented here yet.
"""

from __future__ import annotations

ALLOWED: dict[str, frozenset[str]] = {
    "queued": frozenset({"triaging", "no_access", "excluded", "stale"}),
    "no_access": frozenset({"queued", "excluded"}),
    "excluded": frozenset(),
    "triaging": frozenset({"verifying", "error", "indeterminate", "stale"}),
    "verifying": frozenset({"done", "error", "indeterminate"}),
    "done": frozenset({"needs_review", "triaging"}),
    "needs_review": frozenset({"published", "done"}),
    "published": frozenset({"done"}),
    "error": frozenset({"queued", "triaging"}),
    "indeterminate": frozenset({"queued", "needs_review"}),
    "stale": frozenset({"queued"}),
}

REVIEW_TARGET = {
    "accept": "published",
    "reject": "done",
    "accept_risk": "done",
}


class IllegalTransition(ValueError):
    def __init__(self, current: str, target: str) -> None:
        self.current = current
        self.target = target
        super().__init__(f"{current} -> {target} is not allowed")


class TransitionConflict(ValueError):
    def __init__(self, finding_id: str, current: str) -> None:
        self.finding_id = finding_id
        self.current = current
        super().__init__(f"finding {finding_id} is no longer {current}")


def apply_transition(current: str, target: str) -> str:
    allowed = ALLOWED.get(current)
    if allowed is None or target not in allowed:
        raise IllegalTransition(current, target)
    return target


def cas_status(conn, finding_id: str, current: str, target: str) -> str:
    """Write target only if the row is still `current`.

    Autocommit connections plus a long harness window made a stale
    `needs_review` look like `verifying`; apply_transition then took
    the reject edge (`needs_review → done`).
    """
    nxt = apply_transition(current, target)
    cur = conn.execute(
        "UPDATE findings SET status = ? WHERE id = ? AND status = ?",
        (nxt, finding_id, current),
    )
    if cur.rowcount == 0:
        raise TransitionConflict(finding_id, current)
    return nxt
