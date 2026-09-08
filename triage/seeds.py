"""Load and insert known-tp / known-fp calibration seeds."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from triage.config import REPO_ROOT
from triage.ingest import _synthetic_id

KNOWN_TP_PATH = REPO_ROOT / "data" / "known-tp.jsonl"
KNOWN_FP_PATH = REPO_ROOT / "data" / "known-fp.jsonl"


@dataclass(frozen=True)
class KnownSeed:
    expected: str
    repo_url: str
    sha: str
    rule_id: str
    file: str
    line: int
    severity: str
    scanner_finding_id: str
    scanner_name: str
    description: str
    worktree: str
    harness: str

    @property
    def finding_id(self) -> str:
        return _synthetic_id(self.repo_url, self.sha, self.file, self.line, self.rule_id)


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def load_known() -> list[KnownSeed]:
    seeds: list[KnownSeed] = []
    for row in _read_jsonl(KNOWN_TP_PATH) + _read_jsonl(KNOWN_FP_PATH):
        seeds.append(
            KnownSeed(
                expected=row["expected"],
                repo_url=row["repo_url"],
                sha=row["sha"],
                rule_id=row["rule_id"],
                file=row["file"],
                line=int(row["line"]),
                severity=row["severity"],
                scanner_finding_id=row["scanner_finding_id"],
                scanner_name=row["scanner_name"],
                description=row["description"],
                worktree=row["worktree"],
                harness=row["harness"],
            )
        )
    return seeds


def insert_seed(conn, seed: KnownSeed) -> str:
    fid = seed.finding_id
    meta = {
        "worktree": seed.worktree,
        "harness": seed.harness,
        "expected": seed.expected,
    }
    slug = seed.repo_url.rstrip("/").rsplit("/", 1)[-1]
    conn.execute(
        """
        INSERT INTO findings (
          id, scanner_finding_id, scanner_name, repo_url, repository_name,
          sha, rule_id, file, line, severity, description, scanner_meta_json,
          status, source_kind
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'sast_csv')
        """,
        (
            fid,
            seed.scanner_finding_id,
            seed.scanner_name,
            seed.repo_url,
            slug,
            seed.sha,
            seed.rule_id,
            seed.file,
            seed.line,
            seed.severity,
            seed.description,
            json.dumps(meta, sort_keys=True),
        ),
    )
    return fid


def worktree_for(row, override: Path | None = None, repo_root: Path = REPO_ROOT) -> Path:
    if override is not None:
        return Path(override)
    meta_raw = row["scanner_meta_json"] if "scanner_meta_json" in row.keys() else None
    meta = json.loads(meta_raw or "{}")
    rel = meta.get("worktree")
    if not rel:
        raise ValueError("no worktree: pass --workdir or set scanner_meta_json.worktree")
    return repo_root / rel
