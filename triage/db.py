"""SQLite schema for the triage queue.

The schema is created with `IF NOT EXISTS` so that `make schema` is
idempotent. A runtime `ALTER TABLE` migration handles adding columns to
pre-existing databases without dropping data.

CLI:
    python -m triage.db init [--path triage.db]
        Create the schema. Idempotent.
    python -m triage.db tables [--path triage.db]
        List the tables in the DB.
"""

from __future__ import annotations

import argparse
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from triage.config import CONFIG


_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS findings (
  id                    TEXT PRIMARY KEY,        -- sha256(repo_url|sha|file|line|rule_id)
  scanner_finding_id    TEXT,                    -- scanner's own id; not unique across scanners
  scanner_name          TEXT,                    -- which SAST produced the row
  repo_url              TEXT NOT NULL,
  repository_name       TEXT,                    -- gitlab/github namespace path
  branch                TEXT,                    -- e.g. refs/heads/master
  sha                   TEXT NOT NULL,
  rule_id               TEXT NOT NULL,
  file                  TEXT NOT NULL,
  line                  INTEGER NOT NULL,
  severity              TEXT,                    -- Critical | High | Medium | Low | Info
  scanner_confidence    TEXT,                    -- High | Medium | Low (scanner's, not ours)
  category              TEXT,                    -- security | other | best-practice
  description           TEXT,
  scanner_url           TEXT,                    -- dashboard / finding URL if the scanner has one
  line_of_code_url      TEXT,                    -- host blob URL with sha + path + line
  scanner_meta_json     TEXT,                    -- leftover source columns for forward-compat
  status                TEXT NOT NULL DEFAULT 'queued',
                        -- queued | no_access | excluded | triaging | verifying | done
                        -- | error | indeterminate | stale | needs_review | published
                        -- (no_access: reachable hostname but user lacks read membership; reclassifiable by triage.classify_access)
  exclusion_reason      TEXT,                    -- populated when status='excluded'
  verdict_json          TEXT,                    -- consolidated verdict
  verifier_json         TEXT,                    -- post-verdict replay result
  confidence            REAL,                    -- agent's self-rated confidence (NOT scanner_confidence)
  poc_path              TEXT,
  writeup_path          TEXT,
  attempts              INTEGER NOT NULL DEFAULT 0,
  ingest_run_id         INTEGER,                 -- → ingest_runs.run_id, for audit
  source_kind           TEXT,                    -- sast_csv | hunt | live
  run_id                TEXT,                    -- → runs.id
  entry_location        TEXT,
  sink_location         TEXT,
  created_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at            DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repo_recon (
  repo_url        TEXT NOT NULL,
  sha             TEXT NOT NULL,
  recon_json      TEXT NOT NULL,
  completed_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (repo_url, sha)
);

CREATE TABLE IF NOT EXISTS calibration_runs (
  suite_id        TEXT NOT NULL,               -- e.g. "baseline-2026-05-26"
  finding_id      TEXT NOT NULL,
  expected        TEXT NOT NULL,
                  -- true_positive | true_positive_relocated | false_positive | stale_finding | indeterminate
  actual          TEXT,
  ok              INTEGER,                     -- 0/1
  verdict_json    TEXT,
  ran_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (suite_id, finding_id)
);

-- One row per ingest invocation. Lets us trace any finding back to the file
-- and timestamp that produced it; supports re-ingest idempotency analysis.
CREATE TABLE IF NOT EXISTS ingest_runs (
  run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
  source_kind     TEXT NOT NULL,               -- 'csv'
  source_path     TEXT NOT NULL,
  source_sha256   TEXT,                        -- sha256 of the source file (for csv)
  rows_seen       INTEGER NOT NULL DEFAULT 0,
  rows_inserted   INTEGER NOT NULL DEFAULT 0,
  rows_updated    INTEGER NOT NULL DEFAULT 0,
  rows_unchanged  INTEGER NOT NULL DEFAULT 0,
  rows_rejected   INTEGER NOT NULL DEFAULT 0,
  rejected_path   TEXT,
  notes           TEXT,
  ran_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS engagements (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  org           TEXT NOT NULL,
  policy_json   TEXT NOT NULL DEFAULT '{}',
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
  id                 TEXT PRIMARY KEY,
  engagement_id      TEXT NOT NULL REFERENCES engagements(id),
  mode               TEXT NOT NULL,              -- triage | hunt | live
  playbook           TEXT NOT NULL,
  repo               TEXT NOT NULL,
  sha                TEXT NOT NULL,
  target_url         TEXT,
  status             TEXT NOT NULL,              -- queued | running | cancelled | done | error
  budget_spent_usd   REAL NOT NULL DEFAULT 0,
  started_at         TEXT,
  ended_at           TEXT
);

CREATE TABLE IF NOT EXISTS assets (
  id              TEXT PRIMARY KEY,
  engagement_id   TEXT NOT NULL REFERENCES engagements(id),
  kind            TEXT NOT NULL,
  locator         TEXT NOT NULL,
  meta_json       TEXT
);

CREATE TABLE IF NOT EXISTS proofs (
  id              TEXT PRIMARY KEY,
  finding_id      TEXT NOT NULL REFERENCES findings(id),
  kind            TEXT NOT NULL,
  artifact_uri    TEXT,
  sha256          TEXT,
  replay_json     TEXT
);

CREATE TABLE IF NOT EXISTS chain_hops (
  id              TEXT PRIMARY KEY,
  from_id         TEXT NOT NULL,
  to_id           TEXT NOT NULL,
  kind            TEXT NOT NULL,
  evidence_uri    TEXT
);

CREATE TABLE IF NOT EXISTS knowledge_sources (
  id                TEXT PRIMARY KEY,
  kind              TEXT NOT NULL,               -- pdf | jira | github_issue | github_advisory
  title             TEXT,
  uri               TEXT,
  assessment_date   TEXT,
  sha256            TEXT
);

CREATE TABLE IF NOT EXISTS knowledge_chunks (
  id            TEXT PRIMARY KEY,
  source_id     TEXT NOT NULL REFERENCES knowledge_sources(id),
  locator       TEXT,
  text          TEXT,
  embedding     TEXT,
  meta_json     TEXT
);

CREATE TABLE IF NOT EXISTS tickets (
  id              TEXT PRIMARY KEY,
  finding_id      TEXT NOT NULL REFERENCES findings(id),
  sink            TEXT NOT NULL,
  external_id     TEXT,
  url             TEXT,
  published_at    TEXT
);

CREATE TABLE IF NOT EXISTS tool_spans (
  id              TEXT PRIMARY KEY,
  run_id          TEXT NOT NULL REFERENCES runs(id),
  agent           TEXT,
  tool            TEXT,
  args_hash       TEXT,
  result_sha256   TEXT,
  t               TEXT
);
"""

# Indexes run AFTER column migrations so they can reference newly added
# columns on pre-existing databases.
_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_findings_status    ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_repo      ON findings(repo_url, sha);
CREATE INDEX IF NOT EXISTS idx_findings_rule      ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_repo_name ON findings(repository_name);
CREATE INDEX IF NOT EXISTS idx_findings_scanner   ON findings(scanner_name, scanner_finding_id);

-- Keep updated_at fresh on any UPDATE to findings.
CREATE TRIGGER IF NOT EXISTS findings_updated_at
AFTER UPDATE ON findings
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
  UPDATE findings SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
"""

# Old → new names. Applied before `_FINDINGS_ADDED_COLUMNS` so a rename
# satisfies the add list and we do not create a second empty column.
_FINDINGS_RENAME_COLUMNS: list[tuple[str, str]] = [
    ("semgrep_finding_id", "scanner_finding_id"),
    ("semgrep_confidence", "scanner_confidence"),
    ("semgrep_pro_url", "scanner_url"),
    ("semgrep_meta_json", "scanner_meta_json"),
]

# Columns added to `findings` after the original CREATE TABLE.
# `_migrate_findings_columns` adds any missing one without dropping data.
_FINDINGS_ADDED_COLUMNS: list[tuple[str, str]] = [
    ("scanner_finding_id", "TEXT"),
    ("scanner_name", "TEXT"),
    ("repository_name", "TEXT"),
    ("branch", "TEXT"),
    ("scanner_confidence", "TEXT"),
    ("severity", "TEXT"),
    ("category", "TEXT"),
    ("line_of_code_url", "TEXT"),
    ("scanner_meta_json", "TEXT"),
    ("exclusion_reason", "TEXT"),
    ("ingest_run_id", "INTEGER"),
    ("source_kind", "TEXT"),
    ("run_id", "TEXT"),
    ("entry_location", "TEXT"),
    ("sink_location", "TEXT"),
]


def connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Open (and on first use, create) the triage DB with sane PRAGMAs.

    WAL mode + foreign_keys=ON + a 5s busy_timeout keep the multi-worker
    design honest under contention. Row factory is `sqlite3.Row` so callers
    can use column names.
    """
    path = Path(db_path or CONFIG.db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


@contextmanager
def session(db_path: Path | str | None = None) -> Iterator[sqlite3.Connection]:
    """Context-managed connection with auto-close."""
    conn = connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


def init_schema(db_path: Path | str | None = None) -> Path:
    """Create the schema and migrate any pre-existing DB. Idempotent.

    Order: tables → column migrations → drop removed tables → indexes.
    Migrations introspect via `PRAGMA table_info` because
    `CREATE TABLE IF NOT EXISTS` silently no-ops over an older table
    shape; column adds run after to bring legacy DBs up to date.
    """
    path = Path(db_path or CONFIG.db_path)
    with session(path) as conn:
        conn.executescript(_TABLES_SQL)
        _migrate_findings_renames(conn)
        _migrate_findings_columns(conn)
        _drop_removed_tables(conn)
        conn.executescript(_INDEXES_SQL)
    return path


def _migrate_findings_renames(conn: sqlite3.Connection) -> list[str]:
    """Rename leftover scanner-vendor column names. Returns columns renamed."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    renamed: list[str] = []
    for old, new in _FINDINGS_RENAME_COLUMNS:
        if old in existing and new not in existing:
            conn.execute(f"ALTER TABLE findings RENAME COLUMN {old} TO {new}")
            renamed.append(old)
            existing.discard(old)
            existing.add(new)
    return renamed


def _migrate_findings_columns(conn: sqlite3.Connection) -> list[str]:
    """Add any column listed in `_FINDINGS_ADDED_COLUMNS` that doesn't already exist.

    SQLite has no `ADD COLUMN IF NOT EXISTS`, so we introspect via `PRAGMA
    table_info` first. Returns the list of columns actually added.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    added: list[str] = []
    for col_name, col_def in _FINDINGS_ADDED_COLUMNS:
        if col_name not in existing:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}")
            added.append(col_name)
    return added


_REMOVED_TABLES = ("sheet_rollups",)


def _drop_removed_tables(conn: sqlite3.Connection) -> list[str]:
    """Drop tables the product no longer owns. Findings rows are untouched."""
    existing = {
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    dropped: list[str] = []
    for name in _REMOVED_TABLES:
        if name in existing:
            conn.execute(f"DROP TABLE {name}")
            dropped.append(name)
    return dropped


def list_tables(db_path: Path | str | None = None) -> list[str]:
    with session(db_path) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','index','trigger') ORDER BY type, name"
        ).fetchall()
    return [r["name"] for r in rows]


def list_columns(table: str, db_path: Path | str | None = None) -> list[str]:
    """Return the column names for a table."""
    with session(db_path) as conn:
        return [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m triage.db", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create the schema (idempotent).")
    p_init.add_argument("--path", default=str(CONFIG.db_path),
                        help=f"DB path (default: {CONFIG.db_path}).")

    p_tables = sub.add_parser("tables", help="List schema objects in the DB.")
    p_tables.add_argument("--path", default=str(CONFIG.db_path),
                          help=f"DB path (default: {CONFIG.db_path}).")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "init":
        path = init_schema(args.path)
        objects = list_tables(path)
        print(f"✓ schema initialized at {path}")
        for name in objects:
            print(f"  - {name}")
        return 0

    if args.cmd == "tables":
        for name in list_tables(args.path):
            print(name)
        return 0

    parser.error(f"unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":  # pragma: no cover - exercised by `make schema`
    raise SystemExit(main())
