"""PDF knowledge: ingest with page citations, decay, SHA binding, retention.

A chunk is a hypothesis, never a verdict. PDF bodies are untrusted: text
is redacted and stored, and retrieval hands back a `source_id` + locator
for a hunter to cite. Nothing here writes `runs.scope_json` or
`runs.blast_radius` — the gateway reads those off the run row, which is
what makes an injected instruction in a PDF inert.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import uuid
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Callable

from triage import gateway
from triage.config import REPO_ROOT
from triage.db import init_schema, session
from triage.hunt import merge_or_insert
from triage.status import cas_status
from triage.verifier import strip_replay_passed, verify_finding

KINDS = ("pdf", "jira", "github_issue", "github_advisory")
HALFLIFE_ENV = "KNOWLEDGE_HALFLIFE_DAYS"
DEFAULT_HALFLIFE_DAYS = 365
DECAYED_STATUSES = frozenset({"fixed", "withdrawn"})
DECAYED_WEIGHT = 0.25
REVISION_NOTE = "this was true at another revision."
REDACTED = "[redacted]"

FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "knowledge"
V2_APP_ROOT = FIXTURE_ROOT / "v2-app"
_CANNED_TRANSCRIPT = FIXTURE_ROOT / "transcripts" / "v2-orders.json"

V2_REPO_URL = "https://github.com/acme/v2-app"
V2_SHA = "c" * 40
V2_HOST = "v2.fixture.invalid"
V2_URL = f"https://{V2_HOST}/v2/orders/1"
V2_ENTRY = ("app.py", 1)
NO_PROOF_SHA256 = "0" * 64

# Emails, customer account ids and credentials never reach a chunk: the
# PII gate is code, not a line in a prompt.
_REDACTIONS = (
    re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+"),
    re.compile(r"acct_[A-Za-z0-9]+"),
    re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"bearer\s+[A-Za-z0-9._-]+", re.IGNORECASE),
)


def halflife_days() -> int:
    raw = os.environ.get(HALFLIFE_ENV, "")
    try:
        days = int(raw)
    except ValueError:
        return DEFAULT_HALFLIFE_DAYS
    return days if days > 0 else DEFAULT_HALFLIFE_DAYS


def redact(text: str) -> str:
    for pattern in _REDACTIONS:
        text = pattern.sub(REDACTED, text)
    return text


def default_parse(pdf_bytes: bytes) -> list[dict]:
    """Layout-aware parse, one chunk per heading on a page.

    Docling is imported here rather than at module scope: it drags in
    model weights on first import, the API process never parses on the
    request path without a caller asking for it, and every test injects
    its own `parse`.
    """
    from docling.datamodel.base_models import DocumentStream
    from docling.document_converter import DocumentConverter

    stream = DocumentStream(name="upload.pdf", stream=io.BytesIO(pdf_bytes))
    document = DocumentConverter().convert(stream).document

    chunks: list[dict] = []
    current: dict | None = None
    for item, _level in document.iterate_items():
        text = str(getattr(item, "text", "") or "").strip()
        if not text:
            continue
        prov = getattr(item, "prov", None) or []
        page = prov[0].page_no if prov else 1
        label = str(getattr(item, "label", "")).lower()
        heading = "header" in label or "title" in label
        if current is None or heading or current["page"] != page:
            current = {
                "page": page,
                "heading": text if heading else "",
                "text": "" if heading else text,
            }
            chunks.append(current)
        elif current["text"]:
            current["text"] = f"{current['text']}\n{text}"
        else:
            current["text"] = text
    return chunks


def _default_extract(_chunks: list[dict], *, filename: str, now: datetime) -> dict:
    """Local heuristic stand-in for the offline LLM extract.

    No model call this slice; a wrong structured record would bind a
    chunk to the wrong repo and outrank a correct one.
    """
    return {
        "title": filename,
        "date": now.date().isoformat(),
        "target_app": "",
        "target_sha_or_version": "",
        "vuln_class": "",
        "cwe": "",
        "location": "",
        "status": "unknown",
        "remediation": "",
    }


def _meta(raw: str | None) -> dict:
    try:
        meta = json.loads(raw or "{}")
    except ValueError:
        return {}
    return meta if isinstance(meta, dict) else {}


def _stamp(value: str | None) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def ingest_pdf(
    *,
    db_path: Path | str,
    pdf_bytes: bytes,
    filename: str,
    parse: Callable[[bytes], list[dict]] | None = None,
    extract: Callable[[list[dict]], dict] | None = None,
    now: datetime | None = None,
    sha_hint: str | None = None,
    repo_globs: list[str] | None = None,
    app_name: str | None = None,
    pinned: bool = False,
) -> dict:
    moment = now or datetime.now(timezone.utc)
    parsed = (parse or default_parse)(pdf_bytes)
    record = extract(parsed) if extract else _default_extract(parsed, filename=filename, now=moment)

    source_id = uuid.uuid4().hex
    title = str(record.get("title") or filename)
    assessment_date = record.get("date") or None
    status = str(record.get("status") or "unknown")
    sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    ingested_at = moment.isoformat()

    with session(db_path) as conn:
        conn.execute(
            "INSERT INTO knowledge_sources (id, kind, title, uri, assessment_date, sha256) "
            "VALUES (?, 'pdf', ?, ?, ?, ?)",
            (source_id, title, filename, assessment_date, sha256),
        )
        for chunk in parsed:
            page = int(chunk.get("page") or 1)
            meta = {
                "source_kind": "pdf",
                "page": page,
                "heading": chunk.get("heading") or "",
                "repo_globs": list(repo_globs or []),
                "sha_hint": sha_hint or "",
                "app_name": app_name or record.get("target_app") or "",
                "package_hint": "",
                "ingested_at": ingested_at,
                "assessment_date": assessment_date,
                "status": status,
                "pinned": bool(pinned),
            }
            conn.execute(
                "INSERT INTO knowledge_chunks (id, source_id, locator, text, embedding, meta_json) "
                "VALUES (?, ?, ?, ?, NULL, ?)",
                (
                    uuid.uuid4().hex,
                    source_id,
                    f"p.{page}",
                    redact(str(chunk.get("text") or "")),
                    json.dumps(meta, ensure_ascii=False),
                ),
            )

    return {
        "source_id": source_id,
        "sha256": sha256,
        "chunk_count": len(parsed),
        "title": title,
    }


_CHUNKS_SQL = """
SELECT c.source_id, c.locator, c.text, c.meta_json,
       s.kind AS source_kind, s.title AS source_title
  FROM knowledge_chunks c
  JOIN knowledge_sources s ON s.id = c.source_id
 ORDER BY c.rowid
"""


def _repo_matches(globs: Any, repo: str) -> bool:
    """An unbound chunk is eligible everywhere; a bound one only on a match."""
    if not isinstance(globs, list) or not globs:
        return True
    return any(fnmatch(repo, str(pattern)) for pattern in globs)


def _weight(meta: dict, *, now: datetime, halflife: int) -> float:
    moment = _stamp(meta.get("assessment_date")) or _stamp(meta.get("ingested_at"))
    age_days = max((now - moment).total_seconds() / 86400.0, 0.0) if moment else 0.0
    weight = 0.5 ** (age_days / halflife)
    if str(meta.get("status") or "") in DECAYED_STATUSES:
        weight *= DECAYED_WEIGHT
    return weight


def search(
    *,
    db_path: Path | str,
    query: str,
    kind: str | None = None,
    repo: str | None = None,
    status: str | None = None,
    hunt_sha: str | None = None,
) -> list[dict]:
    """Lexical retrieval over chunk text and source title.

    No embedding model this slice; `knowledge_chunks.embedding` stays
    NULL. Ranking is decay only, so an old or fixed finding cannot
    outrank a current one just by matching more words.
    """
    needle = (query or "").lower()
    now = datetime.now(timezone.utc)
    halflife = halflife_days()

    with session(db_path) as conn:
        rows = conn.execute(_CHUNKS_SQL).fetchall()

    hits: list[dict] = []
    for row in rows:
        if kind is not None and row["source_kind"] != kind:
            continue
        title = row["source_title"] or ""
        text = row["text"] or ""
        if needle not in text.lower() and needle not in title.lower():
            continue
        meta = _meta(row["meta_json"])
        chunk_status = str(meta.get("status") or "")
        if status is not None and chunk_status != status:
            continue
        if repo is not None and not _repo_matches(meta.get("repo_globs"), repo):
            continue
        sha_hint = str(meta.get("sha_hint") or "")
        hits.append(
            {
                "source_id": row["source_id"],
                "locator": row["locator"],
                "text": text,
                "weight": _weight(meta, now=now, halflife=halflife),
                "citation": f"{title} {row['locator']}",
                "revision_note": (
                    REVISION_NOTE if hunt_sha and sha_hint and hunt_sha != sha_hint else ""
                ),
                "status": chunk_status,
            }
        )

    hits.sort(key=lambda hit: hit["weight"], reverse=True)
    return hits


def get(*, db_path: Path | str, source_id: str) -> dict:
    with session(db_path) as conn:
        source = conn.execute(
            "SELECT * FROM knowledge_sources WHERE id = ?", (source_id,)
        ).fetchone()
        if source is None:
            raise ValueError("source not found")
        chunks = conn.execute(
            "SELECT locator, text, meta_json FROM knowledge_chunks "
            "WHERE source_id = ? ORDER BY rowid",
            (source_id,),
        ).fetchall()

    metas = [_meta(chunk["meta_json"]) for chunk in chunks]
    return {
        "id": source["id"],
        "kind": source["kind"],
        "title": source["title"],
        "uri": source["uri"],
        "assessment_date": source["assessment_date"],
        "sha256": source["sha256"],
        "pinned": any(bool(meta.get("pinned")) for meta in metas),
        "chunks": [
            {
                "locator": chunk["locator"],
                "text": chunk["text"],
                "page": int(meta.get("page") or 1),
            }
            for chunk, meta in zip(chunks, metas)
        ],
    }


def get_page(*, db_path: Path | str, source_id: str, page: int) -> dict:
    source = get(db_path=db_path, source_id=source_id)
    locator = f"p.{int(page)}"
    texts = [chunk["text"] for chunk in source["chunks"] if chunk["locator"] == locator]
    if not texts:
        raise ValueError("page not found")
    return {
        "source_id": source_id,
        "page": int(page),
        "locator": locator,
        "text": "\n".join(texts),
        "citation": f"{source['title']} {locator}",
    }


def gc(*, db_path: Path | str, now: datetime | None = None) -> int:
    """Retention: chunks age out after the halflife unless the source is pinned.

    Pinning is copied onto every chunk at ingest, so this never needs to
    join back to the source row.
    """
    moment = now or datetime.now(timezone.utc)
    cutoff_days = halflife_days()

    with session(db_path) as conn:
        rows = conn.execute("SELECT id, meta_json FROM knowledge_chunks").fetchall()
        stale = []
        for row in rows:
            meta = _meta(row["meta_json"])
            if meta.get("pinned"):
                continue
            ingested = _stamp(meta.get("ingested_at"))
            if ingested is None:
                continue
            if (moment - ingested).total_seconds() / 86400.0 > cutoff_days:
                stale.append((row["id"],))
        conn.executemany("DELETE FROM knowledge_chunks WHERE id = ?", stale)
    return len(stale)


def _pdf_escape(text: str) -> str:
    escaped = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    return escaped.encode("latin-1", "replace").decode("latin-1")


def synthetic_pdf(pages: list[str]) -> bytes:
    """A minimal single-font PDF, one object per page.

    The Accept fixture needs a real PDF that no library had to render;
    Docling is for reading operator uploads, not for making test data.
    """
    font_id = 3 + 2 * len(pages)
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [{}] /Count {} >>".format(
            " ".join(f"{3 + 2 * i} 0 R" for i in range(len(pages))), len(pages)
        ).encode("latin-1"),
    ]
    for index, page in enumerate(pages):
        page_id = 3 + 2 * index
        lines = "\n".join(f"({_pdf_escape(line)}) Tj T*" for line in page.splitlines())
        stream = f"BT /F1 11 Tf 14 TL 56 760 Td\n{lines}\nET".encode("latin-1")
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
            f"/Contents {page_id + 1} 0 R >>".encode("latin-1")
        )
        objects.append(
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"
        )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode("latin-1") + body + b"\nendobj\n"

    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode("latin-1")
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode("latin-1")
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode(
        "latin-1"
    )
    return bytes(out)


def _v2_verdict(*, source_id: str, locator: str) -> dict:
    entry = f"{V2_ENTRY[0]}:{V2_ENTRY[1]}"
    return {
        "finding_id": "pending",
        "mode": "hunt",
        "verdict": "true_positive",
        "confidence": 0.85,
        "vuln_class": "CWE-639",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "proof": {"kind": "http_replay", "outcome": "exploited"},
        "scope": {"repo": V2_REPO_URL, "sha": V2_SHA},
        "assumptions": ["/v2/orders/{id} is reachable with another user's id"],
        "counterevidence": "an object-level check would 403 this id",
        "knowledge_used": [
            {"source_id": source_id, "locator": locator, "role": "hypothesis"}
        ],
        "audit_trail": {
            "files_read": [entry],
            "commands_run": [],
            "tool_call_count": 1,
            "wall_time_seconds": 0.4,
        },
        "agent_meta": {"model": "fixture", "posture": "hunt", "pass_number": 1},
    }


def _record_proof(conn, *, run_id: str, proof: dict, transcripts_dir: Path) -> None:
    """Persist the canned transcript and the span that vouches for it.

    Same recipe as the hunt fixture on purpose — `hunt.py` is not
    editable from this slice, so the writer is duplicated rather than
    extracted. The span carries the hash of the bytes actually written;
    a hypothesis naming any other hash fails the verifier's provenance
    gate.
    """
    transcript = json.loads(_CANNED_TRANSCRIPT.read_text(encoding="utf-8"))
    body = gateway.canonical_json_bytes(transcript)
    digest = hashlib.sha256(body).hexdigest()
    transcripts_dir.mkdir(parents=True, exist_ok=True)
    artifact = transcripts_dir / f"{digest}.json"
    artifact.write_bytes(body)

    args = {"method": transcript["request"]["method"], "url": transcript["request"]["url"]}
    conn.execute(
        "INSERT INTO tool_spans (id, run_id, agent, tool, args_hash, result_sha256, t) "
        "VALUES (?, ?, 'hunter', 'http_get', ?, ?, ?)",
        (
            uuid.uuid4().hex,
            run_id,
            hashlib.sha256(gateway.canonical_json_bytes(args)).hexdigest(),
            digest,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    proof["artifact_uri"] = str(artifact)
    proof["artifact_sha256"] = digest


def run_v2_hunt(
    *,
    db_path: Path | str,
    source_id: str,
    locator: str,
    proof: str,
    transcripts_dir: Path | str | None = None,
    execute: Callable[[dict[str, Any]], bytes] | None = None,
) -> dict:
    """Hunt the /v2 fixture on a hypothesis the /v1 PDF suggested.

    The PDF is a reason to look, never a reason to publish: with
    `proof="none"` the hunter cites the chunk and reads /v2 through the
    gateway, and the verifier still refuses the finding because no span
    of this run produced the hash it declared. `proof="v2"` records a
    real capture first, and only then does the row reach
    `needs_review`. Neither path writes `published`.
    """
    if proof not in ("none", "v2"):
        raise ValueError(f"proof must be 'none' or 'v2', got {proof!r}")

    init_schema(db_path)
    out_dir = Path(transcripts_dir) if transcripts_dir else FIXTURE_ROOT / "transcripts"
    execute = execute or (lambda _args: b"ok")

    run_id = f"run-{uuid.uuid4().hex[:12]}"
    engagement_id = f"eng-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    with session(db_path) as conn:
        conn.execute(
            "INSERT INTO engagements (id, name, org, created_at) VALUES (?, ?, ?, ?)",
            (engagement_id, "v2 knowledge fixture", "acme", now),
        )
        conn.execute(
            """
            INSERT INTO runs (id, engagement_id, mode, playbook, repo, sha, status,
                              started_at, scope_json, blast_radius)
            VALUES (?, ?, 'hunt', 'web-app.v1', ?, ?, 'running', ?, ?, 'safe')
            """,
            (
                run_id,
                engagement_id,
                V2_REPO_URL,
                V2_SHA,
                now,
                json.dumps({"repos": [V2_REPO_URL], "hosts": [V2_HOST]}),
            ),
        )

    try:
        gateway.invoke(
            run_id,
            "http_get",
            {"method": "GET", "url": V2_URL},
            db_path=db_path,
            execute=execute,
        )
        looked = True
    except (gateway.OutOfScopeError, gateway.BlastRadiusError, gateway.GatewayCancelled):
        looked = False

    verdict = _v2_verdict(source_id=source_id, locator=locator)
    if proof == "v2":
        with session(db_path) as conn:
            _record_proof(conn, run_id=run_id, proof=verdict["proof"], transcripts_dir=out_dir)
    else:
        # A readable artifact whose hash no span of this run produced:
        # the case the verifier's provenance gate exists to refuse.
        verdict["proof"]["artifact_uri"] = str(_CANNED_TRANSCRIPT)
        verdict["proof"]["artifact_sha256"] = NO_PROOF_SHA256

    finding_id = merge_or_insert(
        db_path=db_path,
        repo_url=V2_REPO_URL,
        sha=V2_SHA,
        vuln_class="authz",
        entry_file=V2_ENTRY[0],
        entry_line=V2_ENTRY[1],
        sink_file=V2_ENTRY[0],
        sink_line=V2_ENTRY[1],
        verdict=strip_replay_passed(verdict),
        run_id=run_id,
    )

    with session(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        if row["status"] != "triaging":
            cas_status(conn, finding_id, row["status"], "triaging")
        cas_status(conn, finding_id, "triaging", "verifying")

    verify_finding(finding_id, db_path)

    with session(db_path) as conn:
        conn.execute("UPDATE runs SET status = 'done' WHERE id = ?", (run_id,))
        status = conn.execute(
            "SELECT status FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()["status"]

    return {
        "engagement_id": engagement_id,
        "run_id": run_id,
        "finding_id": finding_id,
        "status": status,
        "looked": looked,
    }
