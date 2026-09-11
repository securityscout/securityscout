"""Tests for triage/github_org.py.

Every test injects `gh` — no test touches the network. The one live test
is gated on TRIAGE_LIVE_GH=1 and never runs in CI.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from triage import db
from triage import github_org


def _repos_page(*repos: dict) -> tuple[int, str, str]:
    return 0, json.dumps(list(repos)), ""


def _make_gh(repos_by_call: dict[str, tuple[int, str, str]]):
    calls: list[list[str]] = []

    def gh(argv: list[str]) -> tuple[int, str, str]:
        calls.append(argv)
        path = argv[2]
        return repos_by_call.get(path, (0, "{}", ""))

    gh.calls = calls  # type: ignore[attr-defined]
    return gh


class TestImportOrg:
    def test_import_org_writes_engagement_and_assets(self, tmp_path: Path) -> None:
        db_path = tmp_path / "import-test.db"
        gh = _make_gh({
            "orgs/acme/repos": _repos_page({
                "full_name": "acme/app",
                "default_branch": "main",
                "visibility": "PUBLIC",
                "pushed_at": "2026-01-01T00:00:00Z",
            }),
            "repos/acme/app/languages": (0, json.dumps({"Python": 1234}), ""),
        })

        result = github_org.import_org("acme", db_path=db_path, gh=gh)

        assert result["repos"] == [{
            "locator": "acme/app",
            "default_branch": "main",
            "visibility": "public",
            "pushed_at": "2026-01-01T00:00:00Z",
            "languages": {"Python": 1234},
        }]

        with db.session(db_path) as conn:
            eng = conn.execute(
                "SELECT * FROM engagements WHERE id = ?", (result["engagement_id"],)
            ).fetchone()
            assets = conn.execute(
                "SELECT * FROM assets WHERE engagement_id = ?", (result["engagement_id"],)
            ).fetchall()

        assert eng is not None
        assert eng["org"] == "acme"
        assert len(assets) == 1
        asset = assets[0]
        assert asset["kind"] == "repo"
        assert asset["locator"] == "acme/app"
        meta = json.loads(asset["meta_json"])
        assert meta == {
            "default_branch": "main",
            "visibility": "public",
            "pushed_at": "2026-01-01T00:00:00Z",
            "languages": {"Python": 1234},
        }

    def test_languages_fetch_failure_still_succeeds(self, tmp_path: Path) -> None:
        db_path = tmp_path / "import-test.db"
        gh = _make_gh({
            "orgs/acme/repos": _repos_page({
                "full_name": "acme/app",
                "default_branch": "main",
                "visibility": "public",
                "pushed_at": "2026-01-01T00:00:00Z",
            }),
            "repos/acme/app/languages": (1, "", "gh: not found (HTTP 404)\n"),
        })

        result = github_org.import_org("acme", db_path=db_path, gh=gh)
        assert result["repos"][0]["languages"] == {}

    def test_locator_falls_back_to_owner_name_when_no_full_name(
        self, tmp_path: Path,
    ) -> None:
        db_path = tmp_path / "import-test.db"
        gh = _make_gh({
            "orgs/acme/repos": _repos_page({
                "owner": {"login": "Acme"},
                "name": "App",
                "default_branch": "main",
                "visibility": "public",
                "pushed_at": "2026-01-01T00:00:00Z",
            }),
            "repos/acme/app/languages": (0, "{}", ""),
        })

        result = github_org.import_org("acme", db_path=db_path, gh=gh)
        assert result["repos"][0]["locator"] == "acme/app"

    def test_org_list_failure_raises(self, tmp_path: Path) -> None:
        db_path = tmp_path / "import-test.db"
        gh = _make_gh({"orgs/acme/repos": (1, "", "gh: not found (HTTP 404)\n")})

        with pytest.raises(RuntimeError, match="orgs/acme/repos"):
            github_org.import_org("acme", db_path=db_path, gh=gh)

    def test_reimport_creates_a_second_engagement(self, tmp_path: Path) -> None:
        db_path = tmp_path / "import-test.db"
        gh = _make_gh({
            "orgs/acme/repos": _repos_page({
                "full_name": "acme/app", "default_branch": "main",
                "visibility": "public", "pushed_at": "2026-01-01T00:00:00Z",
            }),
            "repos/acme/app/languages": (0, "{}", ""),
        })

        first = github_org.import_org("acme", db_path=db_path, gh=gh)
        second = github_org.import_org("acme", db_path=db_path, gh=gh)

        assert first["engagement_id"] != second["engagement_id"]
        with db.session(db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM engagements WHERE org = 'acme'"
            ).fetchone()[0]
        assert count == 2


def _tarball_bytes(top: str, files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel, content in files.items():
            info = tarfile.TarInfo(name=f"{top}/{rel}")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


class TestCloneAtSha:
    def test_clone_at_sha_extracts_readonly_tree(self, tmp_path: Path) -> None:
        sha = "deadbeefcafebabefeedfacef00dbabe12345678"
        tar_bytes = _tarball_bytes(
            "acme-app-deadbee", {"README.md": b"hello\n", "src/main.py": b"print(1)\n"},
        )

        def gh(argv: list[str]) -> tuple[int, str, str]:
            assert f"repos/acme/app/tarball/{sha}" in argv[2]
            return 0, tar_bytes.decode("latin-1"), ""

        dest_root = tmp_path / "repos"
        result = github_org.clone_at_sha(
            "acme", "app", sha, dest_root=dest_root, gh=gh,
        )

        assert result == dest_root / "acme" / "app" / sha
        assert (result / "README.md").read_bytes() == b"hello\n"
        assert (result / "src" / "main.py").read_bytes() == b"print(1)\n"
        assert not (result / ".git").exists()
        assert not any(result.rglob(".git"))

    def test_tarball_fetch_failure_raises(self, tmp_path: Path) -> None:
        def gh(argv: list[str]) -> tuple[int, str, str]:
            return 1, "", "gh: not found (HTTP 404)\n"

        with pytest.raises(RuntimeError, match="tarball"):
            github_org.clone_at_sha(
                "acme", "app", "deadbeef", dest_root=tmp_path / "repos", gh=gh,
            )

    @pytest.mark.skipif(
        os.environ.get("TRIAGE_LIVE_GH") != "1",
        reason="live gh clone; set TRIAGE_LIVE_GH=1 to run",
    )
    def test_live_clone_at_sha(self, tmp_path: Path) -> None:
        result = github_org.clone_at_sha(
            "cli", "cli", "trunk", dest_root=tmp_path / "repos",
        )
        assert result.exists()
