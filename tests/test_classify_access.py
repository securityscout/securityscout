"""Tests for triage/classify_access.py.

Every test injects `is_repo_accessible` (or the per-strategy `fetch` /
`probe` lower-level boundary) — no test touches the network.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable

import pytest

from triage import classify_access as ca
from triage import db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "classify-test.db"


def _insert_finding(
    conn: sqlite3.Connection,
    *,
    fid: str,
    sf_id: str,
    repo_url: str,
    status: str = "queued",
    rule_id: str = "rule.x",
    sha: str = "deadbeefcafebabefeedfacef00dbabe12345678",
    file_: str = "src/main.py",
    line: int = 1,
) -> None:
    conn.execute(
        """
        INSERT INTO findings (id, scanner_finding_id, repo_url, sha, rule_id, file, line, severity, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'High', ?)
        """,
        (fid, sf_id, repo_url, sha, rule_id, file_, line, status),
    )


def _predicate_from_table(
    table: dict[tuple[str, str], bool | None],
    *,
    default: bool | None = None,
) -> Callable[[str, str], bool | None]:
    """Static predicate keyed by `(host, path)` — anything missing → `default`."""
    def _pred(host: str, path: str) -> bool | None:
        return table.get((host, path), default)
    return _pred


# ---------------------------------------------------------------------------
# repo_url_to_path helper
# ---------------------------------------------------------------------------

class TestRepoUrlToPath:
    def test_strips_git_suffix(self) -> None:
        assert ca.repo_url_to_path("https://gitlab.example.com/g/r.git") == ("gitlab.example.com", "g/r")

    def test_lowercases_both_parts(self) -> None:
        parsed = ca.repo_url_to_path("https://GitLab.Example.COM/Group/Repo")
        assert parsed == ("gitlab.example.com", "group/repo")

    def test_strips_trailing_slash(self) -> None:
        assert ca.repo_url_to_path("https://gitlab.example.com/g/r/") == ("gitlab.example.com", "g/r")

    def test_multi_level_namespace(self) -> None:
        parsed = ca.repo_url_to_path(
            "https://gitlab.example.com/enterprise/space/ds-nodes/svc"
        )
        assert parsed is not None
        assert parsed[1] == "enterprise/space/ds-nodes/svc"

    def test_empty_or_invalid_returns_none(self) -> None:
        assert ca.repo_url_to_path("") is None
        assert ca.repo_url_to_path("not-a-url") is None
        assert ca.repo_url_to_path("https://gitlab.example.com/") is None


# ---------------------------------------------------------------------------
# classify_access — core behaviour, injected predicate
# ---------------------------------------------------------------------------

class TestClassifyAccess:
    def test_accessible_repo_stays_queued(self, tmp_db_path: Path) -> None:
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="a", sf_id="1",
                            repo_url="https://gitlab.example.com/group/repo")

        pred = _predicate_from_table({("gitlab.example.com", "group/repo"): True})
        stats = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert stats.queued_before == 1
        assert stats.queued_after == 1
        assert stats.no_access_after == 0

        with db.session(tmp_db_path) as conn:
            row = conn.execute("SELECT status FROM findings WHERE id='a'").fetchone()
        assert row["status"] == "queued"

    def test_inaccessible_flips_to_no_access(self, tmp_db_path: Path) -> None:
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="b", sf_id="2",
                            repo_url="https://gitlab.example.com/secret/repo")

        pred = _predicate_from_table({("gitlab.example.com", "secret/repo"): False})
        stats = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert stats.queued_after == 0
        assert stats.no_access_after == 1
        assert stats.flipped_to_no_access == [("https://gitlab.example.com/secret/repo", 1)]

        with db.session(tmp_db_path) as conn:
            row = conn.execute("SELECT status FROM findings WHERE id='b'").fetchone()
        assert row["status"] == "no_access"

    def test_predicate_returning_none_leaves_status_unchanged(
        self, tmp_db_path: Path,
    ) -> None:
        """`None` is "I could not ask", not "inaccessible" — the row keeps
        whatever status it had, in both directions. Only an explicit
        False writes no_access."""
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="c1", sf_id="3",
                            repo_url="https://gitlab.com/acme/salesforce/salesforce")
            _insert_finding(conn, fid="c2", sf_id="4",
                            repo_url="https://bitbucket.org/thirddoormedia/site")
            _insert_finding(conn, fid="c3", sf_id="5", status="no_access",
                            repo_url="https://github.com/owner/repo")

        pred = _predicate_from_table({}, default=None)
        stats = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert stats.flipped_to_no_access == []
        assert stats.flipped_to_queued == []
        assert stats.queued_after == 2
        assert stats.no_access_after == 1

        with db.session(tmp_db_path) as conn:
            rows = conn.execute("SELECT id, status FROM findings ORDER BY id").fetchall()
        assert [r["status"] for r in rows] == ["queued", "queued", "no_access"]

    def test_unknown_host_is_counted_and_not_flipped(
        self, tmp_db_path: Path,
    ) -> None:
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="u1", sf_id="20",
                            repo_url="https://github.com/owner/repo")

        stats = ca.classify_access(
            db_path=tmp_db_path, apply=True, hosts=("gitlab.example.com",),
        )
        assert stats.unknown_host_repos == {"github.com": 1}
        assert stats.flipped_to_no_access == []

        with db.session(tmp_db_path) as conn:
            row = conn.execute("SELECT status FROM findings WHERE id = 'u1'").fetchone()
        assert row["status"] == "queued"

    def test_unparseable_repo_url_leaves_status_unchanged(
        self, tmp_db_path: Path,
    ) -> None:
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="p1", sf_id="21", repo_url="not-a-url")

        pred = _predicate_from_table({}, default=False)
        stats = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert stats.unparseable_repos == 1
        assert stats.flipped_to_no_access == []

        with db.session(tmp_db_path) as conn:
            row = conn.execute("SELECT status FROM findings WHERE id = 'p1'").fetchone()
        assert row["status"] == "queued"

    def test_probe_error_on_configured_host_leaves_status_unchanged(
        self, tmp_db_path: Path,
    ) -> None:
        """The configured-host half of the rule: a probe that cannot answer
        is not a negative, so the row keeps its status and the host lands
        in probe_errors rather than in a flip list."""
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="e1", sf_id="23",
                            repo_url="https://gitlab.example.com/acme/app")

        stats = ca.ClassifyStats(probe=ca.PROBE_PER_REPO)
        pred = ca.make_per_repo_predicate(
            ("gitlab.example.com",), probe=lambda _h, _p: None, stats=stats,
        )
        returned = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert stats.probe_errors == {"gitlab.example.com": 1}
        assert returned.flipped_to_no_access == []

        with db.session(tmp_db_path) as conn:
            row = conn.execute("SELECT status FROM findings WHERE id = 'e1'").fetchone()
        assert row["status"] == "queued"

    def test_explicit_false_still_flips_to_no_access(
        self, tmp_db_path: Path,
    ) -> None:
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="f1", sf_id="22",
                            repo_url="https://gitlab.example.com/acme/app")

        pred = _predicate_from_table({}, default=False)
        stats = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert stats.no_access_after == 1

        with db.session(tmp_db_path) as conn:
            row = conn.execute("SELECT status FROM findings WHERE id = 'f1'").fetchone()
        assert row["status"] == "no_access"

    def test_no_access_promoted_back_when_predicate_now_true(
        self, tmp_db_path: Path,
    ) -> None:
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="d", sf_id="6", status="no_access",
                            repo_url="https://gitlab.example.com/team/newly-granted")

        pred = _predicate_from_table({("gitlab.example.com", "team/newly-granted"): True})
        stats = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert stats.no_access_before == 1
        assert stats.queued_after == 1
        assert stats.no_access_after == 0
        assert stats.flipped_to_queued == [
            ("https://gitlab.example.com/team/newly-granted", 1)
        ]

        with db.session(tmp_db_path) as conn:
            row = conn.execute("SELECT status FROM findings WHERE id='d'").fetchone()
        assert row["status"] == "queued"

    @pytest.mark.parametrize("sticky_status", [
        "excluded", "triaging", "verifying", "done",
        "error", "indeterminate", "stale",
    ])
    def test_sticky_statuses_never_touched(
        self, tmp_db_path: Path, sticky_status: str,
    ) -> None:
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="e", sf_id="7", status=sticky_status,
                            repo_url="https://gitlab.example.com/no/access")

        pred = _predicate_from_table({}, default=False)
        stats = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert stats.sticky_rows_skipped == 1
        assert stats.queued_before == 0 and stats.no_access_before == 0

        with db.session(tmp_db_path) as conn:
            row = conn.execute("SELECT status FROM findings WHERE id='e'").fetchone()
        assert row["status"] == sticky_status

    def test_dry_run_does_not_write(self, tmp_db_path: Path) -> None:
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="f", sf_id="8",
                            repo_url="https://gitlab.example.com/no/access")

        pred = _predicate_from_table({}, default=False)
        stats = ca.classify_access(
            db_path=tmp_db_path, apply=False,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert stats.queued_after == 0
        assert stats.no_access_after == 1

        with db.session(tmp_db_path) as conn:
            row = conn.execute("SELECT status FROM findings WHERE id='f'").fetchone()
        assert row["status"] == "queued"

    def test_second_run_is_noop(self, tmp_db_path: Path) -> None:
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            _insert_finding(conn, fid="g1", sf_id="9",
                            repo_url="https://gitlab.example.com/g/in-members")
            _insert_finding(conn, fid="g2", sf_id="10",
                            repo_url="https://gitlab.example.com/g/out-of-members")

        pred = _predicate_from_table({
            ("gitlab.example.com", "g/in-members"): True,
            ("gitlab.example.com", "g/out-of-members"): False,
        })
        first = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert first.queued_after == 1
        assert first.no_access_after == 1

        second = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert second.flipped_to_queued == []
        assert second.flipped_to_no_access == []
        assert second.queued_after == 1
        assert second.no_access_after == 1

    def test_multiple_findings_per_repo_aggregated(self, tmp_db_path: Path) -> None:
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            for i in range(5):
                _insert_finding(
                    conn, fid=f"h{i}", sf_id=str(100 + i),
                    repo_url="https://gitlab.example.com/many/findings",
                    rule_id=f"rule.{i}",
                )

        pred = _predicate_from_table({}, default=False)
        stats = ca.classify_access(
            db_path=tmp_db_path, apply=True,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert stats.flipped_to_no_access == [
            ("https://gitlab.example.com/many/findings", 5)
        ]

    def test_predicate_called_once_per_unique_repo(self, tmp_db_path: Path) -> None:
        """Critical for per_repo probe cost: 5 findings on the same repo
        must produce exactly 1 predicate call, not 5."""
        db.init_schema(tmp_db_path)
        with db.session(tmp_db_path) as conn:
            for i in range(5):
                _insert_finding(
                    conn, fid=f"i{i}", sf_id=str(200 + i),
                    repo_url="https://gitlab.example.com/shared/repo",
                    rule_id=f"rule.{i}",
                )

        calls: list[tuple[str, str]] = []

        def pred(host: str, path: str) -> bool:
            calls.append((host, path))
            return True

        ca.classify_access(
            db_path=tmp_db_path, apply=False,
            hosts=("gitlab.example.com",), is_repo_accessible=pred,
        )
        assert calls == [("gitlab.example.com", "shared/repo")]

    def test_probe_kind_recorded_on_stats(self, tmp_db_path: Path) -> None:
        db.init_schema(tmp_db_path)
        pred = _predicate_from_table({}, default=None)
        stats = ca.classify_access(
            db_path=tmp_db_path, apply=False,
            hosts=("gitlab.example.com",), probe="membership",
            is_repo_accessible=pred,
        )
        assert stats.probe == "membership"

    def test_invalid_probe_raises(self, tmp_db_path: Path) -> None:
        db.init_schema(tmp_db_path)
        with pytest.raises(ValueError, match="unknown probe"):
            ca.classify_access(
                db_path=tmp_db_path, apply=False,
                hosts=("gitlab.example.com",), probe="bogus",
                is_repo_accessible=_predicate_from_table({}),
            )


# ---------------------------------------------------------------------------
# Strategy builders
# ---------------------------------------------------------------------------

class TestMembershipPredicate:
    def test_fetches_once_per_host_and_caches(self) -> None:
        calls: list[str] = []

        def fake_fetch(host: str) -> set[str]:
            calls.append(host)
            return {"g/r"}

        pred = ca.make_membership_predicate(
            ("gitlab.example.com",), fetch_member_paths=fake_fetch,
        )
        assert calls == ["gitlab.example.com"]

        assert pred("gitlab.example.com", "g/r") is True
        assert pred("gitlab.example.com", "other/r") is False
        assert calls == ["gitlab.example.com"]

    def test_unconfigured_host_returns_none(self) -> None:
        pred = ca.make_membership_predicate(
            ("gitlab.example.com",),
            fetch_member_paths=lambda h: {"g/r"},
        )
        assert pred("github.com", "any/path") is None

    def test_populates_member_counts_when_stats_given(self) -> None:
        stats = ca.ClassifyStats()
        ca.make_membership_predicate(
            ("gitlab.example.com",),
            fetch_member_paths=lambda h: {"a/b", "c/d", "e/f"},
            stats=stats,
        )
        assert stats.member_counts == {"gitlab.example.com": 3}

    def test_unknown_host_call_feeds_unknown_host_repos(self) -> None:
        stats = ca.ClassifyStats()
        pred = ca.make_membership_predicate(
            ("gitlab.example.com",),
            fetch_member_paths=lambda h: set(),
            stats=stats,
        )
        pred("github.com", "a/b")
        pred("github.com", "c/d")
        pred("bitbucket.org", "x/y")
        assert stats.unknown_host_repos == {"github.com": 2, "bitbucket.org": 1}


class TestPerRepoPredicate:
    def test_unconfigured_host_returns_none(self) -> None:
        pred = ca.make_per_repo_predicate(
            ("gitlab.example.com",), probe=lambda h, p: True,
        )
        assert pred("github.com", "any/path") is None

    def test_delegates_to_probe(self) -> None:
        seen: list[tuple[str, str]] = []

        def probe(host: str, path: str) -> bool:
            seen.append((host, path))
            return path.startswith("ok/")

        pred = ca.make_per_repo_predicate(
            ("gitlab.example.com",), probe=probe,
        )
        assert pred("gitlab.example.com", "ok/yes") is True
        assert pred("gitlab.example.com", "no/way") is False
        assert seen == [
            ("gitlab.example.com", "ok/yes"),
            ("gitlab.example.com", "no/way"),
        ]

    def test_probe_returning_none_increments_probe_errors(self) -> None:
        stats = ca.ClassifyStats()
        pred = ca.make_per_repo_predicate(
            ("gitlab.example.com",),
            probe=lambda h, p: None,
            stats=stats,
        )
        assert pred("gitlab.example.com", "a/b") is None
        assert pred("gitlab.example.com", "c/d") is None
        assert stats.probe_errors == {"gitlab.example.com": 2}
        # probe errors must NOT also count toward unknown_host_repos —
        # the host IS configured, the call just failed.
        assert stats.unknown_host_repos == {}

    def test_unknown_host_call_feeds_unknown_host_repos_not_probe_errors(self) -> None:
        stats = ca.ClassifyStats()
        called: list[tuple[str, str]] = []
        pred = ca.make_per_repo_predicate(
            ("gitlab.example.com",),
            probe=lambda h, p: called.append((h, p)) or True,
            stats=stats,
        )
        assert pred("github.com", "owner/repo") is None
        assert stats.unknown_host_repos == {"github.com": 1}
        assert stats.probe_errors == {}
        # Off-list host short-circuits before probe — never hits the API.
        assert called == []


# ---------------------------------------------------------------------------
# _probe_repo — output-parsing contract
# ---------------------------------------------------------------------------

class TestProbeRepo:
    def test_rc0_is_accessible(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            ca, "_glab_api_raw",
            lambda host, path: (0, '{"id":179}', ""),
        )
        assert ca._probe_repo("gitlab.example.com", "team/service") is True

    def test_http_404_is_inaccessible(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            ca, "_glab_api_raw",
            lambda host, path: (1, '{"message":"404 Project Not Found"}',
                                "glab: 404 Project Not Found (HTTP 404)\n"),
        )
        assert ca._probe_repo("gitlab.example.com", "ghost/repo") is False

    def test_http_403_is_inaccessible(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            ca, "_glab_api_raw",
            lambda host, path: (1, "", "glab: forbidden (HTTP 403)\n"),
        )
        assert ca._probe_repo("gitlab.example.com", "private/repo") is False

    def test_other_error_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            ca, "_glab_api_raw",
            lambda host, path: (1, "", "glab: connection refused\n"),
        )
        assert ca._probe_repo("gitlab.example.com", "a/b") is None

    def test_url_encodes_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[str] = []

        def fake(host: str, path: str) -> tuple[int, str, str]:
            seen.append(path)
            return 0, '{"id":1}', ""

        monkeypatch.setattr(ca, "_glab_api_raw", fake)
        ca._probe_repo("gitlab.example.com", "team/group/sub/repo")
        assert seen == ["/projects/team%2Fgroup%2Fsub%2Frepo"]


# ---------------------------------------------------------------------------
# Env handling
# ---------------------------------------------------------------------------

class TestHostsToCheck:
    def test_default_is_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Shipping a host with no working probe marks its rows no_access.
        monkeypatch.delenv("TRIAGE_ACCESS_HOSTS", raising=False)
        assert ca.DEFAULT_ACCESS_HOSTS == ()
        assert ca.hosts_to_check() == ()

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRIAGE_ACCESS_HOSTS", "gitlab.example.com, github.com ")
        assert ca.hosts_to_check() == ("gitlab.example.com", "github.com")

    def test_empty_env_means_no_hosts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRIAGE_ACCESS_HOSTS", "")
        assert ca.hosts_to_check() == ()


class TestProbeToUse:
    def test_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRIAGE_ACCESS_PROBE", raising=False)
        assert ca.probe_to_use() == ca.DEFAULT_PROBE
        assert ca.DEFAULT_PROBE == ca.PROBE_PER_REPO

    def test_env_membership(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRIAGE_ACCESS_PROBE", "membership")
        assert ca.probe_to_use() == "membership"

    def test_env_per_repo(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRIAGE_ACCESS_PROBE", "per_repo")
        assert ca.probe_to_use() == "per_repo"

    def test_env_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRIAGE_ACCESS_PROBE", "MEMBERSHIP")
        assert ca.probe_to_use() == "membership"

    def test_env_invalid_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRIAGE_ACCESS_PROBE", "rest_api")
        with pytest.raises(ValueError, match="TRIAGE_ACCESS_PROBE"):
            ca.probe_to_use()
