"""POST /engagements/import: wires the API to triage.github_org.import_org."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage import db


@pytest.fixture(autouse=True)
def _loopback_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRIAGE_API_TOKEN", raising=False)
    monkeypatch.delenv("TRIAGE_API_HOST", raising=False)
    monkeypatch.delenv("TRIAGE_API_PORT", raising=False)


def _client(db_path: Path, gh=None):
    from fastapi.testclient import TestClient

    from api.app import create_app

    db.init_schema(db_path)
    app = create_app(db_path)
    if gh is not None:
        app.state.gh = gh
    return TestClient(app)


def _repos_page(*repos: dict) -> tuple[int, str, str]:
    return 0, json.dumps(list(repos)), ""


def _make_gh(repos_by_call: dict[str, tuple[int, str, str]]):
    def gh(argv: list[str]) -> tuple[int, str, str]:
        path = argv[2]
        return repos_by_call.get(path, (0, "{}", ""))

    return gh


def test_import_org_route_writes_engagement_and_returns_repos(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    gh = _make_gh({
        "orgs/acme/repos": _repos_page({
            "full_name": "acme/app",
            "default_branch": "main",
            "visibility": "public",
            "pushed_at": "2026-01-01T00:00:00Z",
        }),
        "repos/acme/app/languages": (0, json.dumps({"Python": 1234}), ""),
    })
    client = _client(db_path, gh=gh)

    resp = client.post("/engagements/import", json={"org": "acme"})

    assert resp.status_code == 201
    body = resp.json()
    assert body["org"] == "acme"
    assert body["name"] == "acme"
    assert body["policy_json"] == {}
    assert "created_at" in body
    assert body["repos"] == [{
        "locator": "acme/app",
        "default_branch": "main",
        "visibility": "public",
        "pushed_at": "2026-01-01T00:00:00Z",
        "languages": {"Python": 1234},
    }]

    with db.session(db_path) as conn:
        eng = conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (body["id"],)
        ).fetchone()
        assets = conn.execute(
            "SELECT * FROM assets WHERE engagement_id = ?", (body["id"],)
        ).fetchall()
    assert eng is not None
    assert eng["org"] == "acme"
    assert len(assets) == 1
    assert assets[0]["locator"] == "acme/app"


def test_import_empty_org_is_400(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    client = _client(db_path)

    resp = client.post("/engagements/import", json={"org": ""})

    assert resp.status_code == 400
    assert resp.json() == {"error": "invalid_request", "detail": "org is required"}


def test_import_gh_failure_is_502(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    gh = _make_gh({"orgs/acme/repos": (1, "", "gh: not found (HTTP 404)\n")})
    client = _client(db_path, gh=gh)

    resp = client.post("/engagements/import", json={"org": "acme"})

    assert resp.status_code == 502
    body = resp.json()
    assert body["error"] == "upstream"
    assert body["detail"]

    with db.session(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]
    assert count == 0


def test_create_engagement_still_201(tmp_path: Path) -> None:
    db_path = tmp_path / "api.db"
    client = _client(db_path)

    resp = client.post(
        "/engagements",
        json={"name": "app", "org": "acme", "policy_json": {}},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "app"
    assert body["org"] == "acme"
