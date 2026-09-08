"""Per-(repo, SHA) recon. Cached on disk and in repo_recon."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from triage.config import CONFIG, REPO_ROOT
from triage.db import init_schema, session
from triage.model_spawn import complete

ReconSpawn = Callable[[str, str, Path], dict]

_RECON_PROMPT = REPO_ROOT / "prompts" / "recon.prompt.md"
_DEFAULT_CACHE = REPO_ROOT / ".cache" / "recon"


def repo_slug(repo_url: str) -> str:
    path = urlparse(repo_url).path.rstrip("/")
    slug = path.rsplit("/", 1)[-1]
    if slug.endswith(".git"):
        slug = slug[:-4]
    return slug or "repo"


def _render_prompt(repo_url: str, sha: str, worktree: Path) -> str:
    text = _RECON_PROMPT.read_text(encoding="utf-8")
    replacements = {
        "{{REPO_SLUG}}": repo_slug(repo_url),
        "{{REPO_URL}}": repo_url,
        "{{SHA}}": sha,
        "{{LOCAL_PATH}}": str(worktree),
    }
    for token, value in replacements.items():
        text = text.replace(token, value)
    return text


def _default_spawn(prompt: str, model: str, cwd: Path) -> dict:
    return complete(prompt, model, cwd=cwd, mode="plan")


def _store(db_path: Path | str, repo_url: str, sha: str, recon: dict) -> None:
    payload = json.dumps(recon, ensure_ascii=False, sort_keys=True)
    with session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO repo_recon (repo_url, sha, recon_json)
            VALUES (?, ?, ?)
            ON CONFLICT(repo_url, sha) DO UPDATE SET
              recon_json = excluded.recon_json,
              completed_at = CURRENT_TIMESTAMP
            """,
            (repo_url, sha, payload),
        )


def load_recon(db_path: Path | str, repo_url: str, sha: str) -> dict | None:
    with session(db_path) as conn:
        row = conn.execute(
            "SELECT recon_json FROM repo_recon WHERE repo_url = ? AND sha = ?",
            (repo_url, sha),
        ).fetchone()
    if row is None:
        return None
    return json.loads(row["recon_json"])


def ensure_recon(
    repo_url: str,
    sha: str,
    worktree: Path | str,
    *,
    db_path: Path | str,
    cache_dir: Path | str | None = None,
    spawn: ReconSpawn | None = None,
) -> dict:
    cached = load_recon(db_path, repo_url, sha)
    if cached is not None:
        return cached

    cache_root = Path(cache_dir) if cache_dir is not None else _DEFAULT_CACHE
    slug = repo_slug(repo_url)
    cache_path = cache_root / f"{slug}-{sha}.json"
    if cache_path.is_file():
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("recon spawn did not return an object")
        _store(db_path, repo_url, sha, data)
        return data

    runner = spawn or _default_spawn
    data = runner(_render_prompt(repo_url, sha, Path(worktree)), CONFIG.model_recon, Path(worktree))
    if not isinstance(data, dict):
        raise ValueError("recon spawn did not return an object")
    cache_root.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _store(db_path, repo_url, sha, data)
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.recon")
    parser.add_argument("--db", default=str(CONFIG.db_path))
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--workdir", required=True)
    args = parser.parse_args(argv)
    init_schema(args.db)
    try:
        ensure_recon(args.repo_url, args.sha, Path(args.workdir), db_path=args.db)
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as e:
        print(e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
