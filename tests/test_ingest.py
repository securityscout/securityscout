"""Tests for triage/ingest.py — URL parser + end-to-end CSV ingest."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from triage import db, ingest


# ---------------------------------------------------------------------------
# parse_line_of_code_url
# ---------------------------------------------------------------------------

class TestParseLineOfCodeUrl:
    def test_gitlab_with_line(self) -> None:
        url = (
            "https://gitlab.example.com/group/repo/-/blob/"
            "03fb0d60aaf0be38c45aba768676ffaf8a7442f2/app/sub/repository/db_actions.py#L734"
        )
        parts = ingest.parse_line_of_code_url(url)
        assert parts is not None
        assert parts.sha == "03fb0d60aaf0be38c45aba768676ffaf8a7442f2"
        assert parts.file == "app/sub/repository/db_actions.py"
        assert parts.line == 734

    def test_gitlab_without_line_fragment(self) -> None:
        url = (
            "https://gitlab.example.com/group/repo/-/blob/"
            "8f3a9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a/src/main.py"
        )
        parts = ingest.parse_line_of_code_url(url)
        assert parts is not None
        assert parts.line == 0

    def test_github_blob_layout(self) -> None:
        url = (
            "https://github.com/owner/repo/blob/"
            "deadbeefcafebabefeedfacef00dbabe12345678/path/to/file.go#L42"
        )
        parts = ingest.parse_line_of_code_url(url)
        assert parts is not None
        assert parts.sha == "deadbeefcafebabefeedfacef00dbabe12345678"
        assert parts.file == "path/to/file.go"
        assert parts.line == 42

    def test_bitbucket_lines_fragment(self) -> None:
        url = (
            "https://bitbucket.org/org/repo/src/"
            "531daa155c0bb97601ca593a945043b1b58590b0/controllers/admin_assets_controller.php#lines-131"
        )
        parts = ingest.parse_line_of_code_url(url)
        assert parts is not None
        assert parts.sha == "531daa155c0bb97601ca593a945043b1b58590b0"
        assert parts.file == "controllers/admin_assets_controller.php"
        assert parts.line == 131

    def test_short_sha_accepted(self) -> None:
        url = "https://gitlab.example.com/g/r/-/blob/abcdef1/file.py#L1"
        parts = ingest.parse_line_of_code_url(url)
        assert parts is not None
        assert parts.sha == "abcdef1"

    def test_unparseable_returns_none(self) -> None:
        assert ingest.parse_line_of_code_url("") is None
        assert ingest.parse_line_of_code_url("not a url") is None
        assert ingest.parse_line_of_code_url("https://example.com/no-blob/file.py") is None

    def test_sha_lowercased(self) -> None:
        url = "https://gitlab.example.com/g/r/-/blob/DEADBEEFCAFEBABE0123456789ABCDEF01234567/x.py#L1"
        parts = ingest.parse_line_of_code_url(url)
        assert parts is not None
        assert parts.sha == "deadbeefcafebabe0123456789abcdef01234567"


# ---------------------------------------------------------------------------
# normalize_row + validate_row
# ---------------------------------------------------------------------------

def _good_csv_row(**overrides: str) -> dict[str, str]:
    base = {
        "scanner_finding_id": "818243385",
        "rule_id": "python.fastapi.db.generic-sql-fastapi.generic-sql-fastapi",
        "severity": "Critical",
        "confidence": "High",
        "category": "security",
        "scanner_name": "sast",
        "repository_name": "group/repo",
        "repo_url": "https://gitlab.example.com/group/repo",
        "line_of_code_url": (
            "https://gitlab.example.com/group/repo/-/blob/"
            "03fb0d60aaf0be38c45aba768676ffaf8a7442f2/app/sub/repository/db_actions.py#L734"
        ),
        "scanner_url": "https://scanner.example.com/findings/818243385",
        "branch": "refs/heads/master",
        "description": "Untrusted input might be used to build a database query…",
        "export_note": "keep-me",
        "empty_extra": "",
    }
    base.update(overrides)
    return base


class TestNormalizeRow:
    def test_happy_path(self) -> None:
        row, reason = ingest.normalize_row(_good_csv_row())
        assert reason is None and row is not None
        assert row["scanner_finding_id"] == "818243385"
        assert row["sha"] == "03fb0d60aaf0be38c45aba768676ffaf8a7442f2"
        assert row["file"] == "app/sub/repository/db_actions.py"
        assert row["line"] == 734
        assert row["severity"] == "Critical"
        assert row["scanner_name"] == "sast"
        assert row["category"] == "security"
        assert row["branch"] == "refs/heads/master"

    def test_explicit_sha_file_without_blob_url(self) -> None:
        row, reason = ingest.normalize_row(
            _good_csv_row(
                line_of_code_url="",
                sha="03fb0d60aaf0be38c45aba768676ffaf8a7442f2",
                file="app/sub/repository/db_actions.py",
                line="734",
            )
        )
        assert reason is None and row is not None
        assert row["sha"] == "03fb0d60aaf0be38c45aba768676ffaf8a7442f2"
        assert row["file"] == "app/sub/repository/db_actions.py"
        assert row["line"] == 734

    def test_id_is_sha256_of_canonical_tuple(self) -> None:
        row, _ = ingest.normalize_row(_good_csv_row())
        assert row is not None
        assert isinstance(row["id"], str)
        assert len(row["id"]) == 64
        assert all(c in "0123456789abcdef" for c in row["id"])

    def test_unknown_severity_falls_back(self) -> None:
        row, _ = ingest.normalize_row(_good_csv_row(severity="Bogus"))
        assert row is not None
        assert row["severity"] == "Unknown"

    def test_missing_id_rejected(self) -> None:
        row, reason = ingest.normalize_row(_good_csv_row(scanner_finding_id=""))
        assert row is None and reason and "missing scanner_finding_id" in reason

    def test_unparseable_loc_url_rejected(self) -> None:
        row, reason = ingest.normalize_row(
            _good_csv_row(line_of_code_url="https://example.com/no-blob")
        )
        assert row is None and reason and "unparseable" in reason

    def test_meta_json_keeps_unknown_columns(self) -> None:
        row, _ = ingest.normalize_row(_good_csv_row())
        assert row is not None
        import json
        meta = json.loads(row["_scanner_meta_json"])
        assert meta["export_note"] == "keep-me"
        assert "empty_extra" not in meta
        assert "scanner_finding_id" not in meta


class TestValidateRow:
    def test_good_row_passes(self) -> None:
        row, _ = ingest.normalize_row(_good_csv_row())
        assert row is not None
        assert ingest.validate_row(row) is None

    def test_bad_id_pattern_fails(self) -> None:
        row, _ = ingest.normalize_row(_good_csv_row())
        assert row is not None
        row["id"] = "not-a-sha256"
        err = ingest.validate_row(row)
        assert err is not None and "id" in err


# ---------------------------------------------------------------------------
# End-to-end ingest
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_csv(tmp_path: Path) -> Path:
    rows = [
        _good_csv_row(),
        _good_csv_row(
            scanner_finding_id="722222008",
            rule_id="java.spring.security.tainted-ssrf-spring-add.tainted-ssrf-spring-add",
            severity="High",
            repository_name="team/gateway-service",
            repo_url="https://gitlab.example.com/team/gateway-service",
            line_of_code_url=(
                "https://gitlab.example.com/team/gateway-service/-/blob/"
                "9b606845d27e864b6dfbe86f28b94d19feec1143/gateway/src/main/java/com/example/X.java#L225"
            ),
        ),
        _good_csv_row(
            scanner_finding_id="999000001",
            rule_id="php.lang.security.unserialize.unserialize",
            repository_name="exampleorg/example.com",
            repo_url="https://bitbucket.org/exampleorg/example.com",
            line_of_code_url=(
                "https://bitbucket.org/exampleorg/example.com/src/"
                "531daa155c0bb97601ca593a945043b1b58590b0/controllers/admin.php#lines-131"
            ),
        ),
    ]
    path = tmp_path / "sample.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return path


@pytest.fixture()
def tmp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "ingest-test.db"


class TestIngestCsv:
    def test_inserts_each_row(self, tmp_csv: Path, tmp_db_path: Path) -> None:
        stats = ingest.ingest_csv(tmp_csv, db_path=tmp_db_path, exclude_globs=())
        assert stats.rows_seen == 3
        assert stats.rows_inserted == 3
        assert stats.rows_rejected == 0
        with db.session(tmp_db_path) as conn:
            n = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        assert n == 3

    def test_re_ingest_is_idempotent(self, tmp_csv: Path, tmp_db_path: Path) -> None:
        ingest.ingest_csv(tmp_csv, db_path=tmp_db_path, exclude_globs=())
        stats = ingest.ingest_csv(tmp_csv, db_path=tmp_db_path, exclude_globs=())
        assert stats.rows_inserted == 0
        assert stats.rows_unchanged == 3
        with db.session(tmp_db_path) as conn:
            n = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        assert n == 3

    def test_dry_run_writes_nothing(self, tmp_csv: Path, tmp_db_path: Path) -> None:
        stats = ingest.ingest_csv(tmp_csv, db_path=tmp_db_path, dry_run=True, exclude_globs=())
        assert stats.rows_seen == 3
        with db.session(tmp_db_path) as conn:
            n = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            runs = conn.execute("SELECT COUNT(*) FROM ingest_runs").fetchone()[0]
        assert n == 0
        assert runs == 0

    def test_excluded_repo_marked_status_excluded(
        self, tmp_csv: Path, tmp_db_path: Path
    ) -> None:
        stats = ingest.ingest_csv(
            tmp_csv, db_path=tmp_db_path, exclude_globs=("*team/gateway-service*",),
        )
        assert stats.rows_excluded >= 1
        with db.session(tmp_db_path) as conn:
            row = conn.execute(
                "SELECT status, exclusion_reason FROM findings WHERE repo_url = ?",
                ("https://gitlab.example.com/team/gateway-service",),
            ).fetchone()
        assert row is not None
        assert row["status"] == "excluded"
        assert row["exclusion_reason"] is not None

    def test_ingest_run_recorded(self, tmp_csv: Path, tmp_db_path: Path) -> None:
        ingest.ingest_csv(tmp_csv, db_path=tmp_db_path, exclude_globs=())
        with db.session(tmp_db_path) as conn:
            row = conn.execute(
                "SELECT source_kind, rows_seen, rows_inserted, source_sha256 "
                "FROM ingest_runs ORDER BY run_id DESC LIMIT 1"
            ).fetchone()
        assert row is not None
        assert row["source_kind"] == "csv"
        assert row["rows_seen"] == 3
        assert row["rows_inserted"] == 3
        assert row["source_sha256"] is not None and len(row["source_sha256"]) == 64

    def test_status_preserved_on_re_ingest(self, tmp_csv: Path, tmp_db_path: Path) -> None:
        ingest.ingest_csv(tmp_csv, db_path=tmp_db_path, exclude_globs=())
        with db.session(tmp_db_path) as conn:
            conn.execute("UPDATE findings SET status='triaging' WHERE scanner_finding_id='818243385'")
        ingest.ingest_csv(tmp_csv, db_path=tmp_db_path, exclude_globs=())
        with db.session(tmp_db_path) as conn:
            row = conn.execute(
                "SELECT status FROM findings WHERE scanner_finding_id='818243385'"
            ).fetchone()
        assert row["status"] == "triaging"


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------

def test_schema_migration_adds_columns_to_existing_db(tmp_path: Path) -> None:
    """Simulate an older DB with the original column set, then run init_schema."""
    p = tmp_path / "old.db"
    import sqlite3
    conn = sqlite3.connect(p)
    conn.executescript(
        """
        CREATE TABLE findings (
          id TEXT PRIMARY KEY,
          repo_url TEXT NOT NULL,
          sha TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          file TEXT NOT NULL,
          line INTEGER NOT NULL,
          severity TEXT,
          description TEXT,
          status TEXT NOT NULL DEFAULT 'queued',
          attempts INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    conn.commit()
    conn.close()

    db.init_schema(p)
    cols = set(db.list_columns("findings", p))
    for required in ("scanner_finding_id", "branch", "scanner_name",
                     "scanner_meta_json", "ingest_run_id", "exclusion_reason"):
        assert required in cols, f"migration did not add column: {required}"
