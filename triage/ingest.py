"""Generic SAST CSV ingest.

Reads a findings CSV and upserts rows into `findings`.

Required columns:

    scanner_finding_id, rule_id, repo_url

Location — one of:

    sha + file  [+ line]
    line_of_code_url   (GitLab / GitHub / Bitbucket blob URL)

Optional: scanner_name, scanner_url, repository_name, branch, severity,
confidence, category, description. Any other column is kept in
`scanner_meta_json`.

CLI:
    python -m triage.ingest --csv data/csv/<file>.csv [--dry-run]
                            [--exclude-repos GLOB[,GLOB...]]
                            [--db triage.db]

`make ingest CSV=... DRY=1 EXCLUDE=...` is the recommended path.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import json
import os
import re
import sqlite3
import sys
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from triage.config import CONFIG, REPO_ROOT
from triage.db import connect, init_schema

try:
    from jsonschema import Draft202012Validator
except ImportError as e:  # pragma: no cover — jsonschema is a hard dep
    raise SystemExit(
        "triage.ingest requires `jsonschema` — did `make bootstrap-pip` run?"
    ) from e


_FINDING_ROW_SCHEMA_PATH = REPO_ROOT / "data" / "finding-row.schema.json"


# ---------------------------------------------------------------------------
# URL parsing — extract (sha, file, line) from the host's "blob" URL.
# ---------------------------------------------------------------------------

# GitLab:   https://<host>/<ns>/-/blob/<sha>/<path>#L<line>
# GitHub:   https://github.com/<ns>/blob/<sha>/<path>#L<line>
# Bitbucket: https://bitbucket.org/<ns>/src/<sha>/<path>#lines-<line>
_URL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"^https?://[^/]+/.+?/-/blob/(?P<sha>[0-9a-fA-F]{7,40})/"
        r"(?P<path>[^#?]+?)(?:\?[^#]*)?(?:#L(?P<line>\d+))?$"
    ),
    re.compile(
        r"^https?://[^/]+/.+?/blob/(?P<sha>[0-9a-fA-F]{7,40})/"
        r"(?P<path>[^#?]+?)(?:\?[^#]*)?(?:#L(?P<line>\d+))?$"
    ),
    re.compile(
        r"^https?://bitbucket\.org/.+?/src/(?P<sha>[0-9a-fA-F]{7,40})/"
        r"(?P<path>[^#?]+?)(?:\?[^#]*)?(?:#lines?-(?P<line>\d+))?$"
    ),
]


@dataclass(frozen=True)
class LocationParts:
    sha: str
    file: str
    line: int  # 0 = URL didn't expose one; let the agent's anchor step recover.


def parse_line_of_code_url(url: str) -> LocationParts | None:
    """Return (sha, file, line) or None if no host pattern matches.

    Returning None is the caller's signal to reject the row — without a SHA we
    cannot anchor the finding deterministically.
    """
    if not url:
        return None
    for pattern in _URL_PATTERNS:
        m = pattern.match(url.strip())
        if m:
            return LocationParts(
                sha=m.group("sha").lower(),
                file=m.group("path"),
                line=int(m.group("line")) if m.group("line") else 0,
            )
    return None


# ---------------------------------------------------------------------------
# Row normalization — CSV row → DB-shaped dict
# ---------------------------------------------------------------------------

# Default exclude globs are env-driven so deployment-specific repo names
# never land in tracked code. Set `TRIAGE_DEFAULT_EXCLUDE_REPOS` in `.env`
# to a comma-separated list of fnmatch globs (typically deliberately
# vulnerable test-fixture / playground corpora). CLI `--exclude-repos`
# augments this; `--no-default-excludes` skips it entirely.
def _default_exclude_globs() -> tuple[str, ...]:
    raw = os.getenv("TRIAGE_DEFAULT_EXCLUDE_REPOS", "")
    return tuple(g.strip() for g in raw.split(",") if g.strip())


DEFAULT_EXCLUDE_GLOBS: tuple[str, ...] = _default_exclude_globs()


def _synthetic_id(repo_url: str, sha: str, file: str, line: int, rule_id: str) -> str:
    """sha256(repo_url|sha|file|line|rule_id) — content-addressed primary key.

    Stable across re-ingests; collapses duplicate scanner rows (same
    location + rule under two different scanner ids) to one row.
    """
    payload = f"{repo_url}|{sha}|{file}|{line}|{rule_id}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _coerce_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


_KNOWN_CSV_KEYS = {
    "scanner_finding_id", "rule_id", "repo_url", "sha", "file", "line",
    "line_of_code_url", "scanner_name", "scanner_url", "repository_name",
    "branch", "severity", "confidence", "category", "description",
}


def normalize_row(raw: dict[str, str]) -> tuple[dict[str, object] | None, str | None]:
    """Normalize one SAST CSV row into our row-schema shape.

    Returns (row, None) on success or (None, reason) on rejection.
    """
    sf_id = (raw.get("scanner_finding_id") or "").strip()
    rule_id = (raw.get("rule_id") or "").strip()
    repo_url = (raw.get("repo_url") or "").strip()
    loc_url = (raw.get("line_of_code_url") or "").strip()
    sha_raw = (raw.get("sha") or "").strip()
    file_raw = (raw.get("file") or "").strip()
    line_raw = _coerce_int(raw.get("line"))
    if not sf_id:
        return None, "missing scanner_finding_id"
    if not rule_id:
        return None, "missing rule_id"
    if not repo_url:
        return None, "missing repo_url"

    if sha_raw and file_raw:
        parts = LocationParts(
            sha=sha_raw.lower(),
            file=file_raw,
            line=line_raw if line_raw is not None else 0,
        )
    elif loc_url:
        parts = parse_line_of_code_url(loc_url)
        if parts is None:
            return None, f"unparseable line_of_code_url: {loc_url[:120]}"
    else:
        return None, "missing location (need sha+file or line_of_code_url)"

    severity = (raw.get("severity") or "").strip() or "Unknown"
    confidence = (raw.get("confidence") or "").strip() or None
    category = (raw.get("category") or "").strip() or None

    meta = {
        k: v for k, v in raw.items()
        if k not in _KNOWN_CSV_KEYS and (v or "").strip()
    }
    row = {
        "id": _synthetic_id(repo_url, parts.sha, parts.file, parts.line, rule_id),
        "scanner_finding_id": sf_id,
        "scanner_name": (raw.get("scanner_name") or "").strip() or None,
        "repo_url": repo_url,
        "repository_name": (raw.get("repository_name") or "").strip() or None,
        "branch": (raw.get("branch") or "").strip() or None,
        "sha": parts.sha,
        "rule_id": rule_id,
        "file": parts.file,
        "line": parts.line,
        "severity": severity if severity in {
            "Critical", "High", "Medium", "Low", "Info", "Unknown"
        } else "Unknown",
        "scanner_confidence": confidence if confidence in {"High", "Medium", "Low"} else None,
        "category": category,
        "description": (raw.get("description") or "").strip() or None,
        "scanner_url": (raw.get("scanner_url") or "").strip() or None,
        "line_of_code_url": loc_url or None,
        "_scanner_meta_json": json.dumps(meta, ensure_ascii=False, sort_keys=True),
    }
    return row, None


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

_validator: Draft202012Validator | None = None


def _get_validator() -> Draft202012Validator:
    global _validator
    if _validator is None:
        schema = json.loads(_FINDING_ROW_SCHEMA_PATH.read_text(encoding="utf-8"))
        _validator = Draft202012Validator(schema)
    return _validator


def validate_row(row: dict[str, object]) -> str | None:
    """Validate a normalized row against `data/finding-row.schema.json`.

    Returns None on pass; an error message string on fail.
    """
    public = {k: v for k, v in row.items() if not k.startswith("_")}
    errors = sorted(_get_validator().iter_errors(public), key=lambda e: list(e.path))
    if not errors:
        return None
    e0 = errors[0]
    loc = ".".join(str(p) for p in e0.path) or "<root>"
    return f"{loc}: {e0.message}"


# ---------------------------------------------------------------------------
# Source iteration
# ---------------------------------------------------------------------------

@dataclass
class IngestStats:
    rows_seen: int = 0
    rows_inserted: int = 0
    rows_updated: int = 0
    rows_unchanged: int = 0
    rows_rejected: int = 0
    rows_excluded: int = 0
    rejected: list[dict[str, str]] = field(default_factory=list)
    by_repo: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    by_rule_top: dict[str, int] = field(default_factory=dict)
    sha_count: int = 0


def _iter_csv(path: Path) -> Iterator[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            yield row


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_excluded(repo_url: str, repo_name: str | None, globs: Iterable[str]) -> str | None:
    """Return the matching glob (as the exclusion reason) or None."""
    haystacks = [repo_url] + ([repo_name] if repo_name else [])
    for glob in globs:
        for h in haystacks:
            if fnmatch.fnmatchcase(h, glob):
                return f"matched exclude pattern {glob!r}"
    return None


# ---------------------------------------------------------------------------
# DB plumbing — upsert + audit
# ---------------------------------------------------------------------------

# Columns that are written by ingest. The orchestrator's own fields
# (status, verdict_json, verifier_json, confidence, poc_path, writeup_path,
# attempts) are NEVER overwritten on update — re-ingest is for refreshing
# scanner metadata only.
_INGEST_OWNED_COLUMNS = (
    "id",
    "scanner_finding_id",
    "scanner_name",
    "repo_url",
    "repository_name",
    "branch",
    "sha",
    "rule_id",
    "file",
    "line",
    "severity",
    "scanner_confidence",
    "category",
    "description",
    "scanner_url",
    "line_of_code_url",
    "scanner_meta_json",
    "ingest_run_id",
)


def _upsert_finding(
    conn: sqlite3.Connection,
    row: dict[str, object],
    run_id: int,
    excluded_reason: str | None,
) -> str:
    """Insert or refresh one row. Returns 'inserted' | 'updated' | 'unchanged'."""
    cols = list(_INGEST_OWNED_COLUMNS)
    values: dict[str, object] = {
        "id": row["id"],
        "scanner_finding_id": row["scanner_finding_id"],
        "scanner_name": row.get("scanner_name"),
        "repo_url": row["repo_url"],
        "repository_name": row.get("repository_name"),
        "branch": row.get("branch"),
        "sha": row["sha"],
        "rule_id": row["rule_id"],
        "file": row["file"],
        "line": row["line"],
        "severity": row["severity"],
        "scanner_confidence": row.get("scanner_confidence"),
        "category": row.get("category"),
        "description": row.get("description"),
        "scanner_url": row.get("scanner_url"),
        "line_of_code_url": row.get("line_of_code_url"),
        "scanner_meta_json": row.get("_scanner_meta_json"),
        "ingest_run_id": run_id,
    }

    existing = conn.execute(
        "SELECT description, severity, scanner_meta_json, status FROM findings WHERE id = ?",
        (row["id"],),
    ).fetchone()

    if existing is None:
        placeholders = ",".join("?" for _ in cols)
        col_list = ",".join(cols)
        params = [values[c] for c in cols]
        if excluded_reason is not None:
            col_list += ",status,exclusion_reason"
            placeholders += ",?,?"
            params.extend(["excluded", excluded_reason])
        conn.execute(
            f"INSERT INTO findings ({col_list}) VALUES ({placeholders})",
            params,
        )
        return "inserted"

    # Update only the ingest-owned subset; preserve agent state.
    changed = (
        existing["description"] != values["description"]
        or existing["severity"] != values["severity"]
        or existing["scanner_meta_json"] != values["scanner_meta_json"]
    )
    if not changed:
        return "unchanged"

    set_clause = ",".join(f"{c}=?" for c in cols if c != "id")
    params = [values[c] for c in cols if c != "id"]
    params.append(row["id"])
    conn.execute(
        f"UPDATE findings SET {set_clause} WHERE id = ?",
        params,
    )
    return "updated"


def _record_run(
    conn: sqlite3.Connection,
    *,
    source_kind: str,
    source_path: str,
    source_sha256: str | None,
    notes: str | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO ingest_runs (source_kind, source_path, source_sha256, notes)
        VALUES (?, ?, ?, ?)
        """,
        (source_kind, source_path, source_sha256, notes),
    )
    return int(cur.lastrowid or 0)


def _finalize_run(conn: sqlite3.Connection, run_id: int, stats: IngestStats,
                  rejected_path: str | None) -> None:
    conn.execute(
        """
        UPDATE ingest_runs SET
          rows_seen = ?, rows_inserted = ?, rows_updated = ?,
          rows_unchanged = ?, rows_rejected = ?, rejected_path = ?
        WHERE run_id = ?
        """,
        (stats.rows_seen, stats.rows_inserted, stats.rows_updated,
         stats.rows_unchanged, stats.rows_rejected, rejected_path, run_id),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def ingest_csv(
    csv_path: Path,
    *,
    db_path: Path | None = None,
    dry_run: bool = False,
    exclude_globs: Iterable[str] = DEFAULT_EXCLUDE_GLOBS,
    rejected_dir: Path | None = None,
) -> IngestStats:
    """Ingest a SAST CSV into SQLite. Idempotent.

    On dry_run=True nothing is written: we still parse + validate every row
    and return the same stats so the user can preview. The CSV's sha256 is
    captured into ingest_runs.notes for forensic linkage.
    """
    csv_path = Path(csv_path).resolve()
    if not csv_path.exists():
        raise FileNotFoundError(csv_path)

    db_path = Path(db_path or CONFIG.db_path)
    init_schema(db_path)

    src_sha = _file_sha256(csv_path)
    stats = IngestStats()
    rejected_path: Path | None = None
    seen_sha = set()
    rule_counts: dict[str, int] = {}
    excluded_globs = list(exclude_globs)

    with closing(connect(db_path)) as conn:
        if not dry_run:
            run_id = _record_run(
                conn, source_kind="csv", source_path=str(csv_path),
                source_sha256=src_sha,
                notes=f"exclude_globs={excluded_globs!r}",
            )
        else:
            run_id = 0  # not persisted

        for raw in _iter_csv(csv_path):
            stats.rows_seen += 1
            row, reject_reason = normalize_row(raw)
            if reject_reason is not None or row is None:
                stats.rows_rejected += 1
                stats.rejected.append({
                    "scanner_finding_id": (raw.get("scanner_finding_id") or "").strip(),
                    "repo_url": (raw.get("repo_url") or "").strip(),
                    "line_of_code_url": (raw.get("line_of_code_url") or "").strip(),
                    "reason": reject_reason or "<unknown>",
                })
                continue

            schema_err = validate_row(row)
            if schema_err is not None:
                stats.rows_rejected += 1
                stats.rejected.append({
                    "scanner_finding_id": str(row["scanner_finding_id"]),
                    "repo_url": str(row["repo_url"]),
                    "line_of_code_url": str(row.get("line_of_code_url") or ""),
                    "reason": f"schema: {schema_err}",
                })
                continue

            stats.by_repo[str(row["repo_url"])] = stats.by_repo.get(str(row["repo_url"]), 0) + 1
            stats.by_severity[str(row["severity"])] = stats.by_severity.get(str(row["severity"]), 0) + 1
            rule_counts[str(row["rule_id"])] = rule_counts.get(str(row["rule_id"]), 0) + 1
            seen_sha.add(str(row["sha"]))

            excluded_reason = _is_excluded(
                str(row["repo_url"]),
                row.get("repository_name") if isinstance(row.get("repository_name"), str) else None,
                excluded_globs,
            )
            if excluded_reason is not None:
                stats.rows_excluded += 1

            if dry_run:
                # Simulate the same outcome counts so the preview is honest.
                stats.rows_inserted += 1
                continue

            outcome = _upsert_finding(conn, row, run_id, excluded_reason)
            if outcome == "inserted":
                stats.rows_inserted += 1
            elif outcome == "updated":
                stats.rows_updated += 1
            else:
                stats.rows_unchanged += 1

        stats.sha_count = len(seen_sha)
        stats.by_rule_top = dict(sorted(rule_counts.items(), key=lambda x: -x[1])[:10])

        if stats.rejected:
            rd = rejected_dir or (REPO_ROOT / "data" / "ingest-rejects")
            rd.mkdir(parents=True, exist_ok=True)
            ts = csv_path.stem
            rejected_path = rd / f"{ts}-rejects.jsonl"
            if not dry_run:
                with rejected_path.open("w", encoding="utf-8") as f:
                    for r in stats.rejected:
                        f.write(json.dumps(r, ensure_ascii=False) + "\n")

        if not dry_run:
            _finalize_run(conn, run_id, stats, str(rejected_path) if rejected_path else None)

    return stats


# ---------------------------------------------------------------------------
# Pretty-print
# ---------------------------------------------------------------------------

def _print_stats(stats: IngestStats, *, dry_run: bool, db_path: Path) -> None:
    label = "DRY RUN" if dry_run else "INGEST"
    print(f"== {label} summary ==")
    print(f"  rows seen:       {stats.rows_seen}")
    print(f"  inserted:        {stats.rows_inserted}")
    if not dry_run:
        print(f"  updated:         {stats.rows_updated}")
        print(f"  unchanged:       {stats.rows_unchanged}")
    print(f"  rejected:        {stats.rows_rejected}")
    print(f"  excluded (kept in DB, status=excluded): {stats.rows_excluded}")
    print(f"  unique repos:    {len(stats.by_repo)}")
    print(f"  unique SHAs:     {stats.sha_count}")
    print()
    print("  severity breakdown:")
    for k, v in sorted(stats.by_severity.items(), key=lambda x: -x[1]):
        print(f"    {k:<10} {v}")
    print()
    print("  top 8 repos by finding count:")
    for repo, n in sorted(stats.by_repo.items(), key=lambda x: -x[1])[:8]:
        print(f"    {n:>4}  {repo}")
    print()
    print("  top 10 rules by finding count:")
    for rule, n in stats.by_rule_top.items():
        print(f"    {n:>4}  {rule}")
    if stats.rejected:
        print()
        print(f"  ! {stats.rows_rejected} rejected row(s). First 3 reasons:")
        for r in stats.rejected[:3]:
            print(f"    - id={r['scanner_finding_id']!r}: {r['reason']}")
    print()
    if dry_run:
        print(f"  (dry-run; no rows written to {db_path})")
    else:
        print(f"  ✓ committed to {db_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m triage.ingest", description=__doc__)
    parser.add_argument("--csv", required=True, type=Path,
                        help="Path to a SAST findings CSV.")
    parser.add_argument("--db", default=str(CONFIG.db_path), type=Path,
                        help=f"SQLite DB path (default: {CONFIG.db_path}).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse + validate + summarize, but do not write to the DB.")
    parser.add_argument("--exclude-repos", default="",
                        help="Comma-separated fnmatch globs to skip (status=excluded). "
                             "Defaults augment the built-in synthetic-corpus list.")
    parser.add_argument("--no-default-excludes", action="store_true",
                        help="Disable the built-in DEFAULT_EXCLUDE_GLOBS list "
                             "(test-fixture / playground repos).")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    extra = [g.strip() for g in args.exclude_repos.split(",") if g.strip()]
    if args.no_default_excludes:
        globs = tuple(extra)
    else:
        globs = (*DEFAULT_EXCLUDE_GLOBS, *extra)
    stats = ingest_csv(
        args.csv, db_path=args.db, dry_run=args.dry_run, exclude_globs=globs,
    )
    _print_stats(stats, dry_run=args.dry_run, db_path=args.db)
    return 0 if stats.rows_rejected == 0 else 0  # rejects are warnings, not failures


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
