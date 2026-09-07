"""Schema tests for triage/db.py."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from triage import db


@pytest.fixture()
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test-triage.db"


def test_init_schema_creates_required_tables(tmp_db: Path) -> None:
    db.init_schema(tmp_db)
    assert tmp_db.exists()
    objects = set(db.list_tables(tmp_db))
    assert {"findings", "repo_recon", "calibration_runs"}.issubset(objects)
    assert {"idx_findings_status", "idx_findings_repo"}.issubset(objects)


def test_init_schema_is_idempotent(tmp_db: Path) -> None:
    db.init_schema(tmp_db)
    first_mtime = tmp_db.stat().st_mtime
    db.init_schema(tmp_db)
    objects = set(db.list_tables(tmp_db))
    assert {"findings", "repo_recon", "calibration_runs"}.issubset(objects)
    assert tmp_db.stat().st_size > 0
    assert first_mtime <= tmp_db.stat().st_mtime


def test_findings_row_round_trip(tmp_db: Path) -> None:
    db.init_schema(tmp_db)
    with db.session(tmp_db) as conn:
        conn.execute(
            """
            INSERT INTO findings (id, repo_url, sha, rule_id, file, line, severity, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'queued')
            """,
            ("abc123", "https://example.com/repo.git", "deadbeef",
             "java.spring.security.path-traversal", "src/X.java", 42, "ERROR"),
        )
        row = conn.execute("SELECT * FROM findings WHERE id = ?", ("abc123",)).fetchone()
    assert row is not None
    assert row["status"] == "queued"
    assert row["attempts"] == 0
    assert row["created_at"] is not None


def test_updated_at_trigger_fires(tmp_db: Path) -> None:
    db.init_schema(tmp_db)
    with db.session(tmp_db) as conn:
        conn.execute(
            "INSERT INTO findings (id, repo_url, sha, rule_id, file, line) "
            "VALUES ('t1','u','s','r','f',1)"
        )
        before = conn.execute("SELECT updated_at FROM findings WHERE id='t1'").fetchone()["updated_at"]
        conn.execute("UPDATE findings SET status='triaging' WHERE id='t1'")
        after = conn.execute("SELECT updated_at FROM findings WHERE id='t1'").fetchone()["updated_at"]
    assert after >= before


def test_calibration_runs_round_trip(tmp_db: Path) -> None:
    db.init_schema(tmp_db)
    with db.session(tmp_db) as conn:
        conn.execute(
            """
            INSERT INTO calibration_runs
                (suite_id, finding_id, expected, actual, ok)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("baseline-test", "test-finding-001", "true_positive_relocated",
             "true_positive_relocated", 1),
        )
        row = conn.execute(
            "SELECT * FROM calibration_runs WHERE finding_id = ?", ("test-finding-001",)
        ).fetchone()
    assert row is not None
    assert row["ok"] == 1


def test_legacy_semgrep_finding_columns_are_renamed(tmp_path: Path) -> None:
    """Old DBs used vendor-prefixed column names; values must survive."""
    p = tmp_path / "legacy-findings.db"
    conn = sqlite3.connect(p)
    conn.executescript(
        """
        CREATE TABLE findings (
          id TEXT PRIMARY KEY,
          semgrep_finding_id TEXT,
          repo_url TEXT NOT NULL,
          sha TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          file TEXT NOT NULL,
          line INTEGER NOT NULL,
          semgrep_confidence TEXT,
          semgrep_pro_url TEXT,
          semgrep_meta_json TEXT,
          status TEXT NOT NULL DEFAULT 'queued',
          attempts INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO findings (
          id, semgrep_finding_id, repo_url, sha, rule_id, file, line,
          semgrep_confidence, semgrep_pro_url, semgrep_meta_json
        ) VALUES (
          'legacy1', 'ext-42', 'https://example.com/r.git', 'abc1234',
          'rule.x', 'src/a.py', 9, 'High',
          'https://scanner.example.com/findings/42', '{"k":"v"}'
        );
        """
    )
    conn.commit()
    conn.close()

    db.init_schema(p)
    cols = set(db.list_columns("findings", p))
    assert "scanner_finding_id" in cols
    assert "scanner_url" in cols
    assert "scanner_meta_json" in cols
    assert "semgrep_finding_id" not in cols
    with db.session(p) as conn:
        row = conn.execute("SELECT * FROM findings WHERE id='legacy1'").fetchone()
    assert row["scanner_finding_id"] == "ext-42"
    assert row["scanner_url"] == "https://scanner.example.com/findings/42"
    assert row["scanner_meta_json"] == '{"k":"v"}'
    assert row["scanner_confidence"] == "High"


def test_init_schema_drops_sheet_rollups_and_keeps_findings(tmp_path: Path) -> None:
    """Legacy DBs may still have the Google Sheet worklist table."""
    p = tmp_path / "legacy-rollups.db"
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
          status TEXT NOT NULL DEFAULT 'queued',
          attempts INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO findings (id, repo_url, sha, rule_id, file, line)
        VALUES ('keep1', 'https://example.com/r.git', 'abc1234', 'r', 'src/a.py', 3);
        CREATE TABLE sheet_rollups (
          rollup_id INTEGER PRIMARY KEY AUTOINCREMENT,
          gitlab_repo_url TEXT NOT NULL,
          claimed_verdict TEXT
        );
        INSERT INTO sheet_rollups (gitlab_repo_url, claimed_verdict)
        VALUES ('https://example.com/r', 'FP');
        """
    )
    conn.commit()
    conn.close()

    db.init_schema(p)
    objects = set(db.list_tables(p))
    assert "sheet_rollups" not in objects
    with db.session(p) as conn:
        row = conn.execute("SELECT repo_url, file FROM findings WHERE id='keep1'").fetchone()
    assert row["repo_url"] == "https://example.com/r.git"
    assert row["file"] == "src/a.py"


def test_init_schema_on_legacy_db_keeps_rows_and_adds_control_plane_tables(
    tmp_path: Path,
) -> None:
    """Pre-control-plane DBs keep finding rows; new tables and columns appear."""
    p = tmp_path / "legacy-control-plane.db"
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
          status TEXT NOT NULL DEFAULT 'queued',
          attempts INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO findings (id, repo_url, sha, rule_id, file, line)
        VALUES ('keep-legacy', 'https://example.com/r.git', 'abc1234',
                'rule.x', 'src/a.py', 3);
        """
    )
    conn.commit()
    conn.close()

    db.init_schema(p)
    with db.session(p) as conn:
        row = conn.execute(
            "SELECT id, repo_url, sha, rule_id, file, line, status "
            "FROM findings WHERE id='keep-legacy'"
        ).fetchone()
    assert row is not None
    assert row["repo_url"] == "https://example.com/r.git"
    assert row["sha"] == "abc1234"
    assert row["rule_id"] == "rule.x"
    assert row["file"] == "src/a.py"
    assert row["line"] == 3
    assert row["status"] == "queued"

    objects = set(db.list_tables(p))
    for name in (
        "engagements",
        "runs",
        "assets",
        "proofs",
        "chain_hops",
        "knowledge_sources",
        "knowledge_chunks",
        "tickets",
        "tool_spans",
    ):
        assert name in objects

    cols = set(db.list_columns("findings", p))
    for col in ("source_kind", "run_id", "entry_location", "sink_location"):
        assert col in cols


def test_repo_recon_primary_key_enforced(tmp_db: Path) -> None:
    db.init_schema(tmp_db)
    with db.session(tmp_db) as conn:
        conn.execute(
            "INSERT INTO repo_recon (repo_url, sha, recon_json) VALUES (?, ?, ?)",
            ("https://example.com/r.git", "abc", "{}"),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO repo_recon (repo_url, sha, recon_json) VALUES (?, ?, ?)",
                ("https://example.com/r.git", "abc", "{}"),
            )
