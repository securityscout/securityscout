"""Knowledge ingest: PDF, Jira, and GitHub issues; decay; SHA binding.

A chunk is a hypothesis, never a verdict. PDF, Jira, and GitHub
issue bodies are untrusted: text is redacted and stored, and
retrieval hands back a `source_id` + locator for a hunter to cite.
Nothing here writes `runs.scope_json` or `runs.blast_radius` — the
gateway reads those off the run row, which is what makes an injected
instruction inert. GitHub issue ingest authenticates as an app
installation, not with an operator `gh` token.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

from triage import gateway
from triage.config import REPO_ROOT
from triage.db import init_schema, session
from triage.hunt import merge_or_insert
from triage.status import cas_status
from triage.verifier import strip_replay_passed, verify_finding

JiraRunner = Callable[[str, str, dict | None], tuple[int, Any]]
GithubRunner = Callable[[str, str, dict | None], tuple[int, Any]]

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
JIRA_SEARCH_PATH = "/rest/api/3/search/jql"
JIRA_SEARCH_FIELDS = ("summary", "description", "status", "updated", "comment")
JIRA_SEARCH_MAX = 50
JIRA_JQL_MAX = 8192
JIRA_COMMENT_PAGE = 50
JIRA_COMMENT_PAGE_CAP = 20
JIRA_CLOSED_NAMES = frozenset({"closed", "done", "resolved", "fixed"})
GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
GITHUB_USER_AGENT = "security-scout"
GITHUB_SEARCH_PATH = "/search/issues"
GITHUB_SEARCH_MAX = 50
GITHUB_Q_MAX = 256
GITHUB_COMMENT_PAGE = 100
GITHUB_COMMENT_PAGE_CAP = 20
GITHUB_COMMENT_CALL_CAP = 20
GITHUB_DEFAULT_LABELS = ("security", "vulnerability", "advisory")
GITHUB_IAT_SKEW = 60
_IAT: dict[str, Any] = {"token": "", "exp": 0.0}

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

    No model call at ingest; a wrong structured record would bind a
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

    No embedding model; `knowledge_chunks.embedding` stays
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
                "page": None if meta.get("page") is None else int(meta["page"]),
            }
            for chunk, meta in zip(chunks, metas)
        ],
    }


_JIRA_TZ = re.compile(r"([+-]\d{2})(\d{2})$")
_ENRICH_PREFIXES = (("tried", "tried"), ("ruled_out", "ruled out"), ("fix", "fix"))


def runner_from_state(state: Any) -> JiraRunner | None:
    """Prefer `jira_search`. Ignore a ticket sink parked on `jira`.

    `python -m api` sets `app.state.jira` to `DefaultJiraSink` (`create` /
    `comment`). That object is not a JQL runner. A callable on
    `jira_search` or `jira` wins; anything else falls through to the
    library default.
    """
    for name in ("jira_search", "jira"):
        value = getattr(state, name, None)
        if callable(value):
            return value
    return None


def github_runner_from_state(state: Any) -> GithubRunner | None:
    """Prefer `github_search`. Then a callable on `github`.

    A non-callable ticket sink on `github` is ignored. A callable
    there is still used when `github_search` is unset.
    """
    for name in ("github_search", "github"):
        value = getattr(state, name, None)
        if callable(value):
            return value
    return None


def _github_labels() -> list[str]:
    raw = os.environ.get("TRIAGE_GITHUB_ISSUE_LABELS")
    if raw is None:
        return list(GITHUB_DEFAULT_LABELS)
    return [part.strip() for part in raw.split(",") if part.strip()]


def _construct_github_q(query: str) -> str:
    parts = [query]
    lower = query.lower()
    if "is:issue" not in lower and "is:pull-request" not in lower:
        parts.append("is:issue")
    labels = _github_labels()
    if labels:
        parts.append("label:" + ",".join(labels))
    return " ".join(parts)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _openssl_rs256(signing: bytes, key_path: str) -> bytes | None:
    try:
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=signing,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    return proc.stdout


def _github_app_jwt() -> str | None:
    """RS256 JWT for minting an installation token.

    PATH is signed in place. An env PEM is written to a 0o600 temp
    that is unlinked in finally. openssl so this module adds no JWT library.
    """
    app_id = os.environ.get("GITHUB_APP_ID")
    if not app_id:
        return None
    now = int(time.time())
    header = _b64url(b'{"alg":"RS256","typ":"JWT"}')
    payload = _b64url(
        json.dumps(
            {"iat": now - 60, "exp": now + 540, "iss": app_id},
            separators=(",", ":"),
        ).encode()
    )
    signing = f"{header}.{payload}".encode()
    path = (os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH") or "").strip()
    raw = os.environ.get("GITHUB_APP_PRIVATE_KEY")
    if path:
        signature = _openssl_rs256(signing, path)
    elif raw:
        pem = raw.replace("\\n", "\n").encode()
        key_path = ""
        try:
            handle, key_path = tempfile.mkstemp(suffix=".pem")
            os.fchmod(handle, 0o600)
            with os.fdopen(handle, "wb") as keyfile:
                keyfile.write(pem)
            signature = _openssl_rs256(signing, key_path)
        except OSError:
            signature = None
        finally:
            if key_path:
                try:
                    os.unlink(key_path)
                except OSError:
                    pass
    else:
        return None
    if not signature:
        return None
    return f"{header}.{payload}.{_b64url(signature)}"


def _installation_token() -> str | None:
    import httpx

    now = time.time()
    if _IAT["token"] and float(_IAT["exp"] or 0) > now + GITHUB_IAT_SKEW:
        return str(_IAT["token"])
    jwt_token = _github_app_jwt()
    install = os.environ.get("GITHUB_APP_INSTALLATION_ID")
    if not jwt_token or not install:
        return None
    try:
        response = httpx.request(
            "POST",
            f"{GITHUB_API}/app/installations/{install}/access_tokens",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": GITHUB_USER_AGENT,
            },
            json={"permissions": {"issues": "read", "metadata": "read"}},
            timeout=30.0,
        )
    except (httpx.TimeoutException, httpx.HTTPError, OSError):
        return None
    if not (200 <= response.status_code < 300):
        return None
    try:
        body = response.json()
    except ValueError:
        return None
    token = str(body.get("token") or "")
    if not token:
        return None
    exp = _stamp(str(body.get("expires_at") or "").replace("Z", "+00:00"))
    _IAT["token"] = token
    _IAT["exp"] = exp.timestamp() if exp else now + 3600
    return token


def _default_github(method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
    import httpx

    token = _installation_token()
    if not token:
        return -1, {}
    try:
        kwargs: dict[str, Any] = {
            "headers": {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": GITHUB_USER_AGENT,
            },
            "timeout": 30.0,
        }
        if body is not None:
            kwargs["json"] = body
        response = httpx.request(method, f"{GITHUB_API}{path}", **kwargs)
    except (httpx.TimeoutException, httpx.HTTPError, OSError):
        return -1, {}
    if 200 <= response.status_code < 300:
        try:
            return 0, response.json()
        except ValueError:
            return -1, {}
    return response.status_code, {}


def adf_to_text(node: Any) -> str:
    if isinstance(node, str):
        return node
    if not isinstance(node, dict):
        return ""
    if node.get("type") == "text":
        return str(node.get("text") or "")
    content = node.get("content")
    if not isinstance(content, list):
        return ""
    if node.get("type") == "doc":
        parts = [adf_to_text(child) for child in content]
        return "\n".join(part for part in parts if part)
    return "".join(adf_to_text(child) for child in content)


def _default_jira(method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
    import httpx

    base = os.environ.get("JIRA_BASE_URL")
    email = os.environ.get("JIRA_EMAIL")
    token = os.environ.get("JIRA_API_TOKEN")
    if not base or not email or not token:
        return -1, {}
    try:
        kwargs: dict[str, Any] = {}
        if body is not None:
            kwargs["json"] = body
        response = httpx.request(
            method,
            f"{base.rstrip('/')}{path}",
            auth=(email, token),
            timeout=30.0,
            **kwargs,
        )
    except (httpx.TimeoutException, httpx.HTTPError, OSError):
        return -1, {}
    if 200 <= response.status_code < 300:
        try:
            return 0, response.json()
        except ValueError:
            return -1, {}
    return response.status_code, {}


def _jira_assessment_date(updated: Any, moment: datetime) -> str:
    raw = str(updated or "")
    match = _JIRA_TZ.search(raw)
    if match:
        raw = _JIRA_TZ.sub(lambda m: f"{m.group(1)}:{m.group(2)}", raw)
    parsed = _stamp(raw)
    return parsed.date().isoformat() if parsed else moment.date().isoformat()


def _jira_status(fields: dict) -> str:
    status = fields.get("status") if isinstance(fields.get("status"), dict) else {}
    name = str(status.get("name") or "").lower()
    category = status.get("statusCategory")
    key = ""
    if isinstance(category, dict):
        key = str(category.get("key") or "").lower()
    if key == "done" or name in JIRA_CLOSED_NAMES:
        return "fixed"
    return "open"


def _parse_comment_rows(raw_list: Any) -> list[dict]:
    if not isinstance(raw_list, list):
        return []
    comments = []
    for raw in raw_list:
        if not isinstance(raw, dict):
            continue
        author = raw.get("author")
        comments.append(
            {
                "id": str(raw.get("id") or ""),
                "author": str(author.get("displayName") or "") if isinstance(author, dict) else "",
                "created": str(raw.get("created") or ""),
                "text": redact(adf_to_text(raw.get("body"))),
            }
        )
    return comments


def _jira_comments(fields: dict, *, key: str, runner: JiraRunner) -> list[dict]:
    block = fields.get("comment") if isinstance(fields.get("comment"), dict) else {}
    comments = _parse_comment_rows(block.get("comments"))
    total = block.get("total")
    if not isinstance(total, int) or total <= len(comments):
        return comments
    start = len(comments)
    pages = 0
    while start < total and pages < JIRA_COMMENT_PAGE_CAP:
        rc, payload = runner(
            "GET",
            f"/rest/api/3/issue/{key}/comment?startAt={start}&maxResults={JIRA_COMMENT_PAGE}",
            None,
        )
        if rc != 0 or not isinstance(payload, dict):
            break
        extra = _parse_comment_rows(payload.get("comments"))
        if not extra:
            break
        comments.extend(extra)
        start = len(comments)
        pages += 1
    return comments


def _has_enrich_prefix(text: str, prefix: str) -> bool:
    return text.startswith(f"{prefix}:") or text.startswith(f"{prefix} :")


def _jira_enrichment(description: str, comments: list[dict]) -> dict:
    found = {"tried": "", "ruled_out": "", "fix": ""}
    for comment in comments:
        lower = comment["text"].lstrip().lower()
        for key, prefix in _ENRICH_PREFIXES:
            if not found[key] and _has_enrich_prefix(lower, prefix):
                found[key] = comment["text"]
    return {"problem": description, **found}


def _upsert_jira_issue(
    conn,
    issue: dict,
    *,
    moment: datetime,
    runner: JiraRunner,
    sha_hint: str | None,
    repo_globs: list[str] | None,
    app_name: str | None,
    pinned: bool,
) -> dict | None:
    key = str(issue.get("key") or "").strip()
    if not key:
        return None
    fields = issue.get("fields") if isinstance(issue.get("fields"), dict) else {}
    summary = str(fields.get("summary") or key)
    description = redact(adf_to_text(fields.get("description")))
    comments = _jira_comments(fields, key=key, runner=runner)
    status = _jira_status(fields)
    assessment_date = _jira_assessment_date(fields.get("updated"), moment)
    digest = hashlib.sha256(
        gateway.canonical_json_bytes(
            {
                "key": key,
                "summary": summary,
                "description": description,
                "comments": [comment["text"] for comment in comments],
            }
        )
    ).hexdigest()

    existing = conn.execute(
        "SELECT id FROM knowledge_sources WHERE kind = 'jira' AND uri = ?",
        (key,),
    ).fetchone()
    previous_pinned = False
    if existing:
        source_id = existing["id"]
        old = conn.execute(
            "SELECT meta_json FROM knowledge_chunks WHERE source_id = ? ORDER BY rowid",
            (source_id,),
        ).fetchone()
        previous_pinned = bool(_meta(old["meta_json"] if old else None).get("pinned"))
        conn.execute("DELETE FROM knowledge_chunks WHERE source_id = ?", (source_id,))
        conn.execute(
            "UPDATE knowledge_sources SET title = ?, assessment_date = ?, sha256 = ? WHERE id = ?",
            (summary, assessment_date, digest, source_id),
        )
    else:
        source_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO knowledge_sources (id, kind, title, uri, assessment_date, sha256) "
            "VALUES (?, 'jira', ?, ?, ?, ?)",
            (source_id, summary, key, assessment_date, digest),
        )

    meta: dict[str, Any] = {
        "source_kind": "jira",
        "repo_globs": list(repo_globs or []),
        "sha_hint": sha_hint or "",
        "app_name": app_name or "",
        "package_hint": "",
        "ingested_at": moment.isoformat(),
        "assessment_date": assessment_date,
        "status": status,
        "pinned": bool(pinned) or previous_pinned,
        "comments": comments,
    }
    lines = [description]
    if status == "fixed":
        enrich = _jira_enrichment(description, comments)
        meta.update(enrich)
        lines.extend(enrich[key] for key in ("tried", "ruled_out", "fix") if enrich[key])
    conn.execute(
        "INSERT INTO knowledge_chunks (id, source_id, locator, text, embedding, meta_json) "
        "VALUES (?, ?, ?, ?, NULL, ?)",
        (
            uuid.uuid4().hex,
            source_id,
            key,
            "\n".join(part for part in lines if part),
            json.dumps(meta, ensure_ascii=False),
        ),
    )
    return {
        "source_id": source_id,
        "key": key,
        "locator": key,
        "status": status,
        "title": summary,
    }


def search_jql(
    *,
    db_path: Path | str,
    jql: str,
    jira: JiraRunner | None = None,
    now: datetime | None = None,
    sha_hint: str | None = None,
    repo_globs: list[str] | None = None,
    app_name: str | None = None,
    pinned: bool = False,
) -> dict:
    """Live JQL, then persist each issue as a `jira` source.

    Closed issues get a local problem/tried/ruled-out/fix split from the
    comment prefixes. The hunter only ever sees a `source_id` + key —
    retrieved text never lands in a tool argument.
    """
    query = (jql or "").strip()
    if not query:
        raise ValueError("jql is required")
    if len(query) > JIRA_JQL_MAX:
        raise ValueError("jql is too long")
    runner = jira or _default_jira
    rc, payload = runner(
        "POST",
        JIRA_SEARCH_PATH,
        {
            "jql": query,
            "maxResults": JIRA_SEARCH_MAX,
            "fields": list(JIRA_SEARCH_FIELDS),
        },
    )
    if rc != 0 or not isinstance(payload, dict) or not isinstance(payload.get("issues"), list):
        raise RuntimeError("jira search failed")

    moment = now or datetime.now(timezone.utc)
    sources: list[dict] = []
    with session(db_path) as conn:
        for issue in payload["issues"]:
            if not isinstance(issue, dict):
                continue
            written = _upsert_jira_issue(
                conn,
                issue,
                moment=moment,
                runner=runner,
                sha_hint=sha_hint,
                repo_globs=repo_globs,
                app_name=app_name,
                pinned=pinned,
            )
            if written:
                sources.append(written)
    return {"jql": query, "sources": sources}


def _github_assessment_date(updated: Any, moment: datetime) -> str:
    parsed = _stamp(str(updated or "").replace("Z", "+00:00"))
    return parsed.date().isoformat() if parsed else moment.date().isoformat()


def _github_locator(item: dict) -> str | None:
    if item.get("pull_request") is not None:
        return None
    try:
        number = int(item.get("number"))
    except (TypeError, ValueError):
        return None
    parts = str(item.get("repository_url") or "").rstrip("/").split("/")
    if len(parts) < 2:
        return None
    owner, repo = parts[-2], parts[-1]
    if not owner or not repo or repo == "repos":
        return None
    return f"{owner}/{repo}#{number}"


def _parse_github_comment_rows(raw_list: Any) -> list[dict]:
    if not isinstance(raw_list, list):
        return []
    comments = []
    for raw in raw_list:
        if not isinstance(raw, dict):
            continue
        user = raw.get("user")
        comments.append(
            {
                "id": str(raw.get("id") or ""),
                "author": str(user.get("login") or "") if isinstance(user, dict) else "",
                "created": str(raw.get("created_at") or ""),
                "text": redact(str(raw.get("body") or "")),
            }
        )
    return comments


def _github_comments(
    item: dict,
    *,
    locator: str,
    runner: GithubRunner,
    comment_calls: list[int],
) -> list[dict]:
    total = item.get("comments")
    if not isinstance(total, int) or total <= 0:
        return []
    owner_repo, _, number = locator.partition("#")
    owner, _, repo = owner_repo.partition("/")
    comments: list[dict] = []
    page = 1
    first = True
    while len(comments) < total and page <= GITHUB_COMMENT_PAGE_CAP:
        if comment_calls[0] >= GITHUB_COMMENT_CALL_CAP:
            break
        comment_calls[0] += 1
        rc, payload = runner(
            "GET",
            f"/repos/{owner}/{repo}/issues/{number}/comments"
            f"?per_page={GITHUB_COMMENT_PAGE}&page={page}",
            None,
        )
        if rc != 0:
            if first:
                raise RuntimeError("github search failed")
            break
        first = False
        extra = _parse_github_comment_rows(payload)
        if not extra:
            break
        comments.extend(extra)
        page += 1
    return comments


def _upsert_github_issue(
    conn,
    item: dict,
    *,
    moment: datetime,
    runner: GithubRunner,
    sha_hint: str | None,
    repo_globs: list[str] | None,
    app_name: str | None,
    pinned: bool,
    comment_calls: list[int],
) -> dict | None:
    locator = _github_locator(item)
    if not locator:
        return None
    title = str(item.get("title") or locator)
    body = redact(str(item.get("body") or ""))
    comments = _github_comments(
        item, locator=locator, runner=runner, comment_calls=comment_calls
    )
    status = "fixed" if str(item.get("state") or "") == "closed" else "open"
    assessment_date = _github_assessment_date(item.get("updated_at"), moment)
    digest = hashlib.sha256(
        gateway.canonical_json_bytes(
            {
                "locator": locator,
                "title": title,
                "body": body,
                "comments": [comment["text"] for comment in comments],
            }
        )
    ).hexdigest()

    existing = conn.execute(
        "SELECT id FROM knowledge_sources WHERE kind = 'github_issue' AND uri = ?",
        (locator,),
    ).fetchone()
    previous_pinned = False
    if existing:
        source_id = existing["id"]
        old = conn.execute(
            "SELECT meta_json FROM knowledge_chunks WHERE source_id = ? ORDER BY rowid",
            (source_id,),
        ).fetchone()
        previous_pinned = bool(_meta(old["meta_json"] if old else None).get("pinned"))
        conn.execute("DELETE FROM knowledge_chunks WHERE source_id = ?", (source_id,))
        conn.execute(
            "UPDATE knowledge_sources SET title = ?, assessment_date = ?, sha256 = ? WHERE id = ?",
            (title, assessment_date, digest, source_id),
        )
    else:
        source_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO knowledge_sources (id, kind, title, uri, assessment_date, sha256) "
            "VALUES (?, 'github_issue', ?, ?, ?, ?)",
            (source_id, title, locator, assessment_date, digest),
        )

    meta: dict[str, Any] = {
        "source_kind": "github_issue",
        "repo_globs": list(repo_globs or []),
        "sha_hint": sha_hint or "",
        "app_name": app_name or "",
        "package_hint": "",
        "ingested_at": moment.isoformat(),
        "assessment_date": assessment_date,
        "status": status,
        "pinned": bool(pinned) or previous_pinned,
        "comments": comments,
    }
    lines = [body]
    if status == "fixed":
        enrich = _jira_enrichment(body, comments)
        meta.update(enrich)
        lines.extend(enrich[key] for key in ("tried", "ruled_out", "fix") if enrich[key])
    conn.execute(
        "INSERT INTO knowledge_chunks (id, source_id, locator, text, embedding, meta_json) "
        "VALUES (?, ?, ?, ?, NULL, ?)",
        (
            uuid.uuid4().hex,
            source_id,
            locator,
            "\n".join(part for part in lines if part),
            json.dumps(meta, ensure_ascii=False),
        ),
    )
    return {
        "source_id": source_id,
        "locator": locator,
        "status": status,
        "title": title,
    }


def search_issues(
    *,
    db_path: Path | str,
    q: str,
    github: GithubRunner | None = None,
    now: datetime | None = None,
    sha_hint: str | None = None,
    repo_globs: list[str] | None = None,
    app_name: str | None = None,
    pinned: bool = False,
) -> dict:
    """Live GitHub issue search, then persist each hit as a `github_issue` source.

    Closed issues get a local problem/tried/ruled-out/fix split from the
    comment prefixes. The hunter only ever sees a `source_id` + locator —
    retrieved text never lands in a tool argument. Auth is an installation
    token when the default runner is used; nothing here reads `GH_TOKEN`.
    """
    query = (q or "").strip()
    if not query:
        raise ValueError("q is required")
    if len(query) > GITHUB_Q_MAX:
        raise ValueError("q is too long")
    runner = github or _default_github
    qs = urlencode(
        {
            "q": _construct_github_q(query),
            "advanced_search": "true",
            "per_page": str(GITHUB_SEARCH_MAX),
        }
    )
    rc, payload = runner("GET", f"{GITHUB_SEARCH_PATH}?{qs}", None)
    if rc != 0 or not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise RuntimeError("github search failed")

    incomplete = payload.get("incomplete_results") is True
    moment = now or datetime.now(timezone.utc)
    sources: list[dict] = []
    comment_calls = [0]
    with session(db_path) as conn:
        conn.execute("BEGIN")
        try:
            for item in payload["items"]:
                if not isinstance(item, dict):
                    continue
                written = _upsert_github_issue(
                    conn,
                    item,
                    moment=moment,
                    runner=runner,
                    sha_hint=sha_hint,
                    repo_globs=repo_globs,
                    app_name=app_name,
                    pinned=pinned,
                    comment_calls=comment_calls,
                )
                if written:
                    sources.append(written)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return {"q": query, "sources": sources, "incomplete": incomplete}


def get_thread(*, db_path: Path | str, source_id: str) -> dict:
    with session(db_path) as conn:
        source = conn.execute(
            "SELECT id FROM knowledge_sources WHERE id = ?", (source_id,)
        ).fetchone()
        if source is None:
            raise ValueError("source not found")
        chunks = conn.execute(
            "SELECT locator, meta_json FROM knowledge_chunks "
            "WHERE source_id = ? ORDER BY rowid",
            (source_id,),
        ).fetchall()
    first = chunks[0] if chunks else None
    raw = _meta(first["meta_json"]).get("comments") if first else []
    comments = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            comments.append(
                {
                    "id": str(item.get("id") or ""),
                    "author": str(item.get("author") or ""),
                    "created": str(item.get("created") or ""),
                    "text": str(item.get("text") or ""),
                }
            )
    return {
        "source_id": source["id"],
        "locator": first["locator"] if first else "",
        "comments": comments,
    }


def previews(*, db_path: Path | str, source_ids: list[str]) -> list[dict]:
    """List/create preview rows for `source_ids`, one session, first chunk each."""
    if not source_ids:
        return []
    placeholders = ",".join("?" * len(source_ids))
    with session(db_path) as conn:
        sources = {
            row["id"]: row
            for row in conn.execute(
                f"SELECT * FROM knowledge_sources WHERE id IN ({placeholders})",
                source_ids,
            )
        }
        chunks = conn.execute(
            f"SELECT source_id, locator, text, meta_json FROM knowledge_chunks "
            f"WHERE source_id IN ({placeholders}) ORDER BY rowid",
            source_ids,
        ).fetchall()
    first_by: dict[str, Any] = {}
    for chunk in chunks:
        first_by.setdefault(chunk["source_id"], chunk)
    out = []
    for sid in source_ids:
        source = sources.get(sid)
        if source is None:
            continue
        first = first_by.get(sid)
        meta = _meta(first["meta_json"]) if first else {}
        locator = first["locator"] if first else ""
        out.append(
            {
                "id": source["id"],
                "kind": source["kind"],
                "title": source["title"],
                "uri": source["uri"],
                "assessment_date": source["assessment_date"],
                "sha256": source["sha256"],
                "citation": f"{source['title']} {locator}".strip() if locator else source["title"] or "",
                "page": None if meta.get("page") is None else int(meta["page"]),
                "page_text": first["text"] if first else "",
            }
        )
    return out


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
    edited from knowledge ingest, so the writer is duplicated rather
    than extracted. The span carries the hash of the bytes actually written;
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
