"""GitHub org inventory: import an org's repos and clone one at a pinned SHA.

`import_org` writes one `engagements` row plus one `assets` row per repo
(`kind="repo"`), reusing the existing `engagements` and `assets`
tables — no new DDL.
`clone_at_sha` fetches a tarball snapshot via `gh`, not `git clone`: the
extracted tree has no `.git`, so there is nothing to push and
TRIAGE_READONLY_TARGET_REPOS holds by construction.

Both go through one injectable `gh(argv: list[str]) -> (rc, stdout, stderr)`
runner so tests never touch the network. The default runner always closes
stdin and decodes with `latin-1` so a binary tarball round-trips through
the same `str` channel as JSON responses.
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from triage.db import init_schema, session

GhRunner = Callable[[list[str]], tuple[int, str, str]]


def _gh_run(argv: list[str], *, timeout: float = 60.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv, capture_output=True, encoding="latin-1",
            stdin=subprocess.DEVNULL, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return -1, "", f"{type(exc).__name__}: {exc}"
    return proc.returncode, proc.stdout, proc.stderr


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _locator(repo: dict[str, Any]) -> str:
    full_name = repo.get("full_name")
    if full_name:
        return full_name.lower()
    owner = (repo.get("owner") or {}).get("login", "")
    name = repo.get("name", "")
    return f"{owner}/{name}".lower()


def import_org(org: str, *, db_path: Path | str, gh: GhRunner | None = None) -> dict[str, Any]:
    """Import `org`'s repos as one engagement + one asset per repo.

    Re-importing the same org creates another engagement — POST
    /engagements is not idempotent today, so this does not upsert either.
    """
    gh = gh or _gh_run
    rc, out, err = gh(["gh", "api", f"orgs/{org}/repos", "--paginate"])
    if rc != 0:
        raise RuntimeError(
            f"gh api orgs/{org}/repos --paginate -> rc={rc}: {(err or out).strip()[:200]}"
        )
    repos_raw = json.loads(out)

    repos: list[dict[str, Any]] = []
    for repo in repos_raw:
        locator = _locator(repo)
        lrc, lout, _lerr = gh(["gh", "api", f"repos/{locator}/languages"])
        languages = json.loads(lout) if lrc == 0 else {}
        repos.append({
            "locator": locator,
            "default_branch": repo.get("default_branch"),
            "visibility": (repo.get("visibility") or "").lower(),
            "pushed_at": repo.get("pushed_at"),
            "languages": languages,
        })

    init_schema(db_path)
    engagement_id = uuid.uuid4().hex
    with session(db_path) as conn:
        conn.execute(
            "INSERT INTO engagements (id, name, org, policy_json, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (engagement_id, org, org, "{}", _now()),
        )
        conn.executemany(
            "INSERT INTO assets (id, engagement_id, kind, locator, meta_json) "
            "VALUES (?, ?, 'repo', ?, ?)",
            [
                (
                    uuid.uuid4().hex, engagement_id, repo["locator"],
                    json.dumps({
                        "default_branch": repo["default_branch"],
                        "visibility": repo["visibility"],
                        "pushed_at": repo["pushed_at"],
                        "languages": repo["languages"],
                    }),
                )
                for repo in repos
            ],
        )

    return {"engagement_id": engagement_id, "repos": repos}


def clone_at_sha(
    owner: str, name: str, sha: str, *,
    dest_root: Path | str | None = None, gh: GhRunner | None = None,
) -> Path:
    """Extract `owner/name`@`sha` read-only to `dest_root/owner/name/sha`.

    Fetches `gh api repos/<owner>/<name>/tarball/<sha>` — a point-in-time
    snapshot, not a git clone — and strips GitHub's added top-level
    directory so the repo root lands directly at `sha`.
    """
    gh = gh or _gh_run
    dest_root = Path(dest_root) if dest_root is not None else Path.cwd() / "repos"
    dest = dest_root / owner / name / sha

    rc, out, err = gh(["gh", "api", f"repos/{owner}/{name}/tarball/{sha}"])
    if rc != 0:
        raise RuntimeError(
            f"gh api repos/{owner}/{name}/tarball/{sha} -> rc={rc}: "
            f"{(err or out).strip()[:200]}"
        )

    dest.mkdir(parents=True, exist_ok=True)
    data = out.encode("latin-1")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        members = tar.getmembers()
        prefixes = {m.name.split("/", 1)[0] for m in members if "/" in m.name}
        top = prefixes.pop() if len(prefixes) == 1 else None
        for member in members:
            rel = member.name
            if top and rel.startswith(f"{top}/"):
                rel = rel[len(top) + 1:]
            if not rel or rel == "." or ".." in Path(rel).parts:
                continue
            member.name = rel
            tar.extract(member, path=dest)

    return dest
