"""Knowledge sources: list, source detail, cited page, PDF upload."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

from api.app import ApiError
from triage import db, knowledge

router = APIRouter()


class PdfUpload(BaseModel):
    filename: str
    content_b64: str


def _preview(source: dict[str, Any]) -> dict[str, Any]:
    """List/create payload: the source row plus its first chunk as a citation.

    The page text rides along so the screen can open the cited page from
    the list it already fetched, rather than a request per source.
    """
    first = source["chunks"][0] if source["chunks"] else None
    return {
        "id": source["id"],
        "kind": source["kind"],
        "title": source["title"],
        "uri": source["uri"],
        "assessment_date": source["assessment_date"],
        "sha256": source["sha256"],
        "citation": f"{source['title']} {first['locator']}" if first else "",
        "page": first["page"] if first else None,
        "page_text": first["text"] if first else "",
    }


@router.get("/knowledge")
def list_knowledge(request: Request, kind: str | None = None) -> dict[str, Any]:
    if kind is not None and kind not in knowledge.KINDS:
        raise ApiError(400, "invalid_request", f"kind must be one of {', '.join(knowledge.KINDS)}")
    db_path = request.app.state.db_path
    with db.session(db_path) as conn:
        ids = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM knowledge_sources WHERE (? IS NULL OR kind = ?) ORDER BY id",
                (kind, kind),
            )
        ]
    return {
        "sources": [_preview(knowledge.get(db_path=db_path, source_id=sid)) for sid in ids],
        "halflife_days": knowledge.halflife_days(),
    }


@router.get("/knowledge/{source_id}")
def get_knowledge(source_id: str, request: Request) -> dict[str, Any]:
    try:
        source = knowledge.get(db_path=request.app.state.db_path, source_id=source_id)
    except ValueError as exc:
        raise ApiError(404, "not_found", "source not found") from exc
    return source


@router.get("/knowledge/{source_id}/pages/{page}")
def get_knowledge_page(source_id: str, page: int, request: Request) -> dict[str, Any]:
    db_path = request.app.state.db_path
    try:
        knowledge.get(db_path=db_path, source_id=source_id)
    except ValueError as exc:
        raise ApiError(404, "not_found", "source not found") from exc
    try:
        return knowledge.get_page(db_path=db_path, source_id=source_id, page=page)
    except ValueError as exc:
        raise ApiError(404, "not_found", "page not found") from exc


@router.post("/knowledge/pdf", status_code=201)
def post_knowledge_pdf(body: PdfUpload, request: Request) -> dict[str, Any]:
    """Ingest one uploaded PDF.

    `parse` / `extract` come off the app state so a test never has to
    construct Docling; unset, the library defaults apply. A parse failure
    is reported as a fixed string — the exception text can carry the
    upload path and the converter's own filesystem layout.
    """
    filename = body.filename.strip()
    if not filename:
        raise ApiError(400, "invalid_request", "filename is required")
    try:
        pdf_bytes = base64.b64decode(body.content_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ApiError(400, "invalid_request", "content_b64 is not valid base64") from exc
    if not pdf_bytes:
        raise ApiError(400, "invalid_request", "content_b64 is empty")

    db_path = request.app.state.db_path
    try:
        ingested = knowledge.ingest_pdf(
            db_path=db_path,
            pdf_bytes=pdf_bytes,
            filename=filename,
            parse=getattr(request.app.state, "parse", None),
            extract=getattr(request.app.state, "extract", None),
        )
    except Exception as exc:  # noqa: BLE001
        raise ApiError(400, "invalid_request", "could not parse pdf") from exc
    return _preview(knowledge.get(db_path=db_path, source_id=ingested["source_id"]))
