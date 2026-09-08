"""Classify each finding's access posture against a live access predicate.

For each `repo_url` in the reclassifiable subset of `findings`, decide
whether the configured user can read it, and update `status`:

    queued     → no_access   (lost or never had access)
    no_access  → queued      (access regained; e.g., membership granted)
    queued     → queued      (still accessible, or unprobeable)
    no_access  → no_access   (still inaccessible, or unprobeable)

Sticky statuses (excluded, triaging, verifying, done, error,
indeterminate, stale) are never touched. `excluded` in particular is a
user policy decision (set by ingest globs) and outranks live access.

Two probe strategies live behind a single `is_repo_accessible(host, path)`
predicate interface:

* ``per_repo`` (default) — one `glab api /projects/<encoded_path>` per
  unique repo. 200 = accessible, 404/403 = no_access. Catches access
  paths the membership probe misses: group-inherited access, namespace
  renames that redirect, ad-hoc shares.

* ``membership`` — one paginated `/projects?membership=true` per host,
  then set lookup against `path_with_namespace`. Cheap but only sees
  *direct* membership; misses inheritance and redirects.

Hosts NOT listed in TRIAGE_ACCESS_HOSTS have no auth surface wired up,
so they cannot be probed at all and their rows are left alone.

The probe is injectable as `is_repo_accessible: (host, path) -> bool | None`
so tests run fully offline:
  * True  → accessible (queued)
  * False → not accessible (no_access)
  * None  → could not ask (row keeps its status, tracked separately)

Writing `no_access` takes an explicit `False`. A host nobody can probe,
an ambiguous probe, and an unparseable `repo_url` all leave the row
untouched — silently marking them inaccessible is indistinguishable
from a real access loss.

CLI:
    python -m triage.classify_access [--apply] [--db triage.db]
                                     [--hosts h1,h2] [--probe per_repo|membership]

Makefile:
    make classify-access                       # dry-run, default probe
    make classify-access COMMIT=1              # apply
    make classify-access PROBE=membership      # opt into the cheap probe
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import quote, urlparse

from triage.config import CONFIG
from triage.db import connect, init_schema


# Hosts for which we know how to consult a live access API. Empty by
# default: `glab` is the only probe implemented, and listing a host it
# cannot answer for would classify that host's repos on a probe that
# never runs. Set TRIAGE_ACCESS_HOSTS once the matching auth surface
# exists.
DEFAULT_ACCESS_HOSTS: tuple[str, ...] = ()

# Only rows in these statuses are reclassifiable. Everything else is sticky
# (a user/orchestrator decision classify_access must not override).
RECLASSIFIABLE_STATUSES: tuple[str, ...] = ("queued", "no_access")

PROBE_PER_REPO = "per_repo"
PROBE_MEMBERSHIP = "membership"
VALID_PROBES: tuple[str, ...] = (PROBE_PER_REPO, PROBE_MEMBERSHIP)
DEFAULT_PROBE = PROBE_PER_REPO

_GLAB_PAGE_SIZE = 100
_GLAB_MAX_PAGES = 50  # 5000-repo safety bound

AccessPredicate = Callable[[str, str], bool | None]


@dataclass
class ClassifyStats:
    """One run's outcome — both raw counts and per-repo flip lists."""

    probe: str = DEFAULT_PROBE
    # Membership probe only: how many membership_projects per host.
    member_counts: dict[str, int] = field(default_factory=dict)
    queued_before: int = 0
    no_access_before: int = 0
    queued_after: int = 0
    no_access_after: int = 0
    sticky_rows_skipped: int = 0
    # Repos that resolved to a host not in TRIAGE_ACCESS_HOSTS.
    unknown_host_repos: dict[str, int] = field(default_factory=dict)
    # Per-repo probe only: how many times the predicate returned None on
    # a *configured* host — transient API error, rate limit, etc.
    probe_errors: dict[str, int] = field(default_factory=dict)
    # Unique repo_url values that did not parse into (host, path).
    unparseable_repos: int = 0

    flipped_to_queued: list[tuple[str, int]] = field(default_factory=list)
    flipped_to_no_access: list[tuple[str, int]] = field(default_factory=list)


def hosts_to_check() -> tuple[str, ...]:
    """Return the lower-cased host list to query. Env-overridable."""
    raw = os.getenv("TRIAGE_ACCESS_HOSTS")
    if raw is None:
        return DEFAULT_ACCESS_HOSTS
    return tuple(h.strip().lower() for h in raw.split(",") if h.strip())


def probe_to_use() -> str:
    """Return the active probe strategy. Env-overridable."""
    raw = (os.getenv("TRIAGE_ACCESS_PROBE") or "").strip().lower()
    if not raw:
        return DEFAULT_PROBE
    if raw not in VALID_PROBES:
        raise ValueError(
            f"TRIAGE_ACCESS_PROBE={raw!r} not in {VALID_PROBES}"
        )
    return raw


def repo_url_to_path(repo_url: str) -> tuple[str, str] | None:
    """`(host, namespace_path)`, lowercased and `.git`-stripped. None if unparseable."""
    if not repo_url:
        return None
    u = urlparse(repo_url)
    if not u.netloc:
        return None
    path = u.path.strip("/").lower().removesuffix(".git")
    if not path:
        return None
    return u.netloc.lower(), path


# ---------------------------------------------------------------------------
# Probe primitives — wrapped so tests can monkeypatch the boundary.
# ---------------------------------------------------------------------------


def _glab_api_raw(
    host: str, path: str, *, timeout: float = 30.0
) -> tuple[int, str, str]:
    """Run `glab api --hostname <host> <path>` and return (rc, stdout, stderr).

    Always closes stdin; glab inherits stdin and blocks forever otherwise.
    Does NOT raise on non-zero exit — callers decide how to interpret it
    (per_repo probe needs to distinguish 404 from other failures).
    """
    proc = subprocess.run(
        ["glab", "api", "--hostname", host, path],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _fetch_member_paths(host: str) -> set[str]:
    """Return the user's direct-membership project paths on `host`, lowercased."""
    paths: set[str] = set()
    for page in range(1, _GLAB_MAX_PAGES + 1):
        rc, out, err = _glab_api_raw(
            host,
            f"/projects?membership=true&per_page={_GLAB_PAGE_SIZE}&page={page}&simple=true",
        )
        if rc != 0:
            raise RuntimeError(
                f"glab api --hostname {host} /projects?membership=true page={page} -> "
                f"rc={rc}: {(err or out).strip()[:200]}"
            )
        chunk = json.loads(out)
        if not isinstance(chunk, list) or not chunk:
            break
        for proj in chunk:
            name = proj.get("path_with_namespace")
            if name:
                paths.add(name.lower())
        if len(chunk) < _GLAB_PAGE_SIZE:
            break
    return paths


def _probe_repo(host: str, path: str) -> bool | None:
    """Single-project access probe via `glab api /projects/<encoded_path>`.

    Returns True (200), False (404/403), or None (anything else — the
    caller leaves the row alone and reports the host).

    GitLab returns 404 (not 403) for projects the caller can't read, by
    design (info-leak hardening). 403 is still handled defensively in
    case a host is configured differently.
    """
    encoded = quote(path, safe="")
    rc, _out, err = _glab_api_raw(host, f"/projects/{encoded}")
    if rc == 0:
        return True
    err_blob = (err or "").lower()
    if "(http 404)" in err_blob or "(http 403)" in err_blob:
        return False
    return None


# ---------------------------------------------------------------------------
# Strategy builders — both yield an AccessPredicate.
# ---------------------------------------------------------------------------


def make_membership_predicate(
    hosts: tuple[str, ...],
    *,
    fetch_member_paths: Callable[[str], set[str]] = _fetch_member_paths,
    stats: ClassifyStats | None = None,
) -> AccessPredicate:
    """Predicate backed by a one-shot per-host membership fetch.

    Membership lists are eager-fetched at build time (one paginated call
    per host). When `stats` is given, populates `member_counts` up-front
    and `unknown_host_repos` lazily as off-list hosts are seen.
    """
    hosts_set = {h.lower() for h in hosts}
    cache: dict[str, set[str]] = {h: fetch_member_paths(h) for h in hosts_set}
    if stats is not None:
        stats.member_counts = {h: len(v) for h, v in cache.items()}

    def predicate(host: str, path: str) -> bool | None:
        if host not in hosts_set:
            if stats is not None:
                stats.unknown_host_repos[host] = stats.unknown_host_repos.get(host, 0) + 1
            return None
        return path in cache[host]

    return predicate


def make_per_repo_predicate(
    hosts: tuple[str, ...],
    *,
    probe: Callable[[str, str], bool | None] = _probe_repo,
    stats: ClassifyStats | None = None,
) -> AccessPredicate:
    """Predicate backed by one `glab api /projects/<path>` per unique repo.

    When `stats` is given, off-list hosts feed `unknown_host_repos` and
    probes that come back ambiguous on configured hosts feed
    `probe_errors` — kept as separate buckets so the end-of-run summary
    can tell "host I can't talk to" apart from "host I can, but this
    one call failed". Both return `None`, which leaves the row alone.
    """
    hosts_set = {h.lower() for h in hosts}

    def predicate(host: str, path: str) -> bool | None:
        if host not in hosts_set:
            if stats is not None:
                stats.unknown_host_repos[host] = stats.unknown_host_repos.get(host, 0) + 1
            return None
        outcome = probe(host, path)
        if outcome is None and stats is not None:
            stats.probe_errors[host] = stats.probe_errors.get(host, 0) + 1
        return outcome

    return predicate


# ---------------------------------------------------------------------------
# Core reclassification
# ---------------------------------------------------------------------------


def classify_access(
    *,
    db_path: Path | None = None,
    apply: bool = False,
    hosts: tuple[str, ...] | None = None,
    probe: str | None = None,
    is_repo_accessible: AccessPredicate | None = None,
) -> ClassifyStats:
    """Reclassify access on every reclassifiable finding row.

    With `apply=False` (default) the DB is read-only and stats describe
    what *would* happen. `is_repo_accessible` is injectable so tests can
    bypass `glab` entirely; if not supplied, a default predicate is built
    from `probe` (or env) and `hosts`.
    """
    db_path = Path(db_path or CONFIG.db_path)
    init_schema(db_path)

    hosts_lower = tuple(h.lower() for h in (hosts or hosts_to_check()))
    probe_kind = (probe or probe_to_use()).lower()
    if probe_kind not in VALID_PROBES:
        raise ValueError(f"unknown probe {probe_kind!r}; want one of {VALID_PROBES}")

    stats = ClassifyStats(probe=probe_kind)
    if is_repo_accessible is None:
        if probe_kind == PROBE_MEMBERSHIP:
            is_repo_accessible = make_membership_predicate(hosts_lower, stats=stats)
        else:
            is_repo_accessible = make_per_repo_predicate(hosts_lower, stats=stats)

    with connect(db_path) as conn:
        placeholders = ",".join("?" for _ in RECLASSIFIABLE_STATUSES)
        rows = conn.execute(
            f"SELECT id, repo_url, status FROM findings WHERE status IN ({placeholders})",
            RECLASSIFIABLE_STATUSES,
        ).fetchall()

        stats.sticky_rows_skipped = int(conn.execute(
            f"SELECT COUNT(*) FROM findings WHERE status NOT IN ({placeholders})",
            RECLASSIFIABLE_STATUSES,
        ).fetchone()[0])

        # Predicate is called once per unique repo_url — critical so the
        # per_repo probe scales with #repos, not #findings.
        decisions: dict[str, str | None] = {}
        flip_q_by_repo: dict[str, int] = {}
        flip_n_by_repo: dict[str, int] = {}
        to_update: list[tuple[str, str]] = []  # (new_status, finding_id)

        for r in rows:
            repo_url = r["repo_url"]
            current = r["status"]
            if current == "queued":
                stats.queued_before += 1
            elif current == "no_access":
                stats.no_access_before += 1

            # `None` is a cached decision of its own ("could not ask"), so
            # membership decides the cache hit, not truthiness.
            if repo_url not in decisions:
                decisions[repo_url] = _decide_for_repo(
                    repo_url, is_repo_accessible, stats,
                )
            decision = decisions[repo_url]

            if decision is not None and decision != current:
                to_update.append((decision, r["id"]))
                bucket = flip_q_by_repo if decision == "queued" else flip_n_by_repo
                bucket[repo_url] = bucket.get(repo_url, 0) + 1

        if apply and to_update:
            conn.executemany(
                "UPDATE findings SET status = ? WHERE id = ?", to_update,
            )

        flipped_q = sum(flip_q_by_repo.values())
        flipped_n = sum(flip_n_by_repo.values())
        stats.queued_after = stats.queued_before - flipped_n + flipped_q
        stats.no_access_after = stats.no_access_before + flipped_n - flipped_q
        stats.flipped_to_queued = sorted(flip_q_by_repo.items(), key=lambda kv: -kv[1])
        stats.flipped_to_no_access = sorted(flip_n_by_repo.items(), key=lambda kv: -kv[1])

    return stats


def _decide_for_repo(
    repo_url: str, is_repo_accessible: AccessPredicate, stats: ClassifyStats,
) -> str | None:
    """`True` → queued, `False` → no_access, `None` → leave the row alone.

    The predicate owns the per-host diagnostics (unknown_host_repos,
    probe_errors); an unparseable URL never reaches it, so it is counted
    here instead.
    """
    parsed = repo_url_to_path(repo_url)
    if parsed is None:
        stats.unparseable_repos += 1
        return None
    host, path = parsed
    outcome = is_repo_accessible(host, path)
    if outcome is None:
        return None
    return "queued" if outcome else "no_access"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_stats(stats: ClassifyStats, *, apply: bool, db_path: Path,
                 hosts: tuple[str, ...]) -> None:
    label = "CLASSIFY-ACCESS (APPLIED)" if apply else "CLASSIFY-ACCESS (dry-run)"
    print(f"== {label} ==")
    print(f"  db:               {db_path}")
    print(f"  probe:            {stats.probe}")
    print(f"  hosts queried:    {', '.join(hosts) if hosts else '(none)'}")
    for host, n in stats.member_counts.items():
        print(f"    {host:25s}  membership_projects={n}")
    print()
    print(f"  reclassifiable rows considered: {stats.queued_before + stats.no_access_before}")
    print(f"    queued (before):     {stats.queued_before}")
    print(f"    no_access (before):  {stats.no_access_before}")
    print(f"  sticky rows skipped:  {stats.sticky_rows_skipped}")
    print()
    print(f"  flipped queued → no_access:  {sum(n for _, n in stats.flipped_to_no_access)}")
    print(f"  flipped no_access → queued:  {sum(n for _, n in stats.flipped_to_queued)}")
    print()
    print(f"  queued (after):     {stats.queued_after}")
    print(f"  no_access (after):  {stats.no_access_after}")

    if stats.flipped_to_no_access:
        print()
        print("  top 10 repos flipping to no_access:")
        for repo, n in stats.flipped_to_no_access[:10]:
            print(f"    {n:>4}  {repo}")

    if stats.flipped_to_queued:
        print()
        print("  top 10 repos flipping to queued:")
        for repo, n in stats.flipped_to_queued[:10]:
            print(f"    {n:>4}  {repo}")

    if stats.unknown_host_repos:
        print()
        print("  repos on unconfigured hosts (left unchanged):")
        for host, n in sorted(stats.unknown_host_repos.items(), key=lambda kv: -kv[1]):
            print(f"    {n:>4}  {host}  (add to TRIAGE_ACCESS_HOSTS to enable live check)")

    if stats.probe_errors:
        print()
        print("  per-repo probe errors (left unchanged; investigate):")
        for host, n in sorted(stats.probe_errors.items(), key=lambda kv: -kv[1]):
            print(f"    {n:>4}  {host}")

    if stats.unparseable_repos:
        print()
        print(f"  unparseable repo_url values (left unchanged):  {stats.unparseable_repos}")

    print()
    if apply:
        print(f"  ✓ committed to {db_path}")
    else:
        print("  (dry-run; pass --apply or `make classify-access COMMIT=1` to write)")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m triage.classify_access", description=__doc__)
    parser.add_argument("--db", default=str(CONFIG.db_path), type=Path,
                        help=f"SQLite DB path (default: {CONFIG.db_path}).")
    parser.add_argument("--apply", action="store_true",
                        help="Write changes. Default is dry-run.")
    parser.add_argument("--hosts", default="",
                        help="Override TRIAGE_ACCESS_HOSTS (comma-separated). "
                             "Repos on other hosts are left unchanged.")
    parser.add_argument("--probe", default=None, choices=VALID_PROBES,
                        help=f"Probe strategy (default: env TRIAGE_ACCESS_PROBE "
                             f"or {DEFAULT_PROBE}).")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    hosts = (
        tuple(h.strip().lower() for h in args.hosts.split(",") if h.strip())
        if args.hosts else None
    )
    stats = classify_access(
        db_path=args.db, apply=args.apply, hosts=hosts, probe=args.probe,
    )
    _print_stats(stats, apply=args.apply, db_path=args.db,
                 hosts=hosts or hosts_to_check())
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
