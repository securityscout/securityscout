"""Attack graph: the findings of one engagement and the hops between them."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from api.app import ApiError
from triage import db

router = APIRouter()

# Either end puts the hop on this engagement's graph. Matching only
# `from_id` would drop the inbound half of a cross-engagement hop while
# the node query still listed the finding it lands on — a node with no
# edge, which reads as "nothing reached this" rather than "the other end
# is somewhere else".
_HOPS_SQL = """
SELECT DISTINCT h.id, h.from_id, h.to_id, h.kind, h.evidence_uri
  FROM chain_hops h
  JOIN findings f ON f.id IN (h.from_id, h.to_id)
  JOIN runs r     ON r.id = f.run_id
 WHERE r.engagement_id = ?
 ORDER BY h.id
"""

# A node is a finding of this engagement that a hop actually touches;
# an unchained finding belongs on the findings table, not on the graph.
_NODES_SQL = """
SELECT DISTINCT f.id, f.file, f.line
  FROM findings f
  JOIN runs r ON r.id = f.run_id
 WHERE r.engagement_id = ?
   AND f.id IN (SELECT from_id FROM chain_hops UNION SELECT to_id FROM chain_hops)
 ORDER BY f.id
"""


@router.get("/engagements/{engagement_id}/graph")
def get_graph(engagement_id: str, request: Request) -> dict[str, Any]:
    with db.session(request.app.state.db_path) as conn:
        exists = conn.execute(
            "SELECT 1 FROM engagements WHERE id = ?", (engagement_id,)
        ).fetchone()
        if exists is None:
            raise ApiError(404, "not_found", "engagement not found")
        nodes = conn.execute(_NODES_SQL, (engagement_id,)).fetchall()
        hops = conn.execute(_HOPS_SQL, (engagement_id,)).fetchall()
    return {
        "engagement_id": engagement_id,
        "nodes": [
            {"id": n["id"], "kind": "finding", "label": f"{n['file']}:{n['line']}"}
            for n in nodes
        ],
        "hops": [
            {
                "id": h["id"],
                "from_id": h["from_id"],
                "to_id": h["to_id"],
                "kind": h["kind"],
                "evidence_uri": h["evidence_uri"],
            }
            for h in hops
        ],
    }
