"""Acceptance tests for the chain hop writer and the attack-graph route.

Offline: the transcript is canned and the seed writes its own engagement,
run, findings and span — no model call, no network.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from triage import chain, db


@pytest.fixture(autouse=True)
def _no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRIAGE_API_TOKEN", raising=False)


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    p = tmp_path / "graph-test.db"
    db.init_schema(p)
    return p


def _client(db_path: Path):
    from fastapi.testclient import TestClient

    from api.app import create_app

    return TestClient(create_app(db_path))


def _seed_second_engagement(db_path: Path) -> dict[str, str]:
    """A second engagement whose single finding a hop can land on."""
    ids = {"engagement_id": "eng-two", "run_id": "run-two", "finding_id": "finding-two"}
    with db.session(db_path) as conn:
        conn.execute(
            "INSERT INTO engagements (id, name, org, created_at) VALUES (?, ?, ?, ?)",
            (ids["engagement_id"], "second", "acme", "2026-01-01T00:00:00+00:00"),
        )
        conn.execute(
            """
            INSERT INTO runs (id, engagement_id, mode, playbook, repo, sha, status)
            VALUES (?, ?, 'hunt', 'web-app.v1', ?, ?, 'done')
            """,
            (ids["run_id"], ids["engagement_id"], chain.FIXTURE_REPO_URL, chain.FIXTURE_SHA),
        )
        conn.execute(
            """
            INSERT INTO findings (id, repo_url, sha, rule_id, file, line, status,
                                  source_kind, run_id)
            VALUES (?, ?, ?, 'hunt.rce', 'app/jobs.py', 5, 'done', 'hunt', ?)
            """,
            (ids["finding_id"], chain.FIXTURE_REPO_URL, chain.FIXTURE_SHA, ids["run_id"]),
        )
    return ids


def test_seed_writes_two_findings_and_one_hop(db_path: Path, tmp_path: Path) -> None:
    seeded = chain.seed_two_hop(db_path=db_path, transcripts_dir=tmp_path / "transcripts")

    with db.session(db_path) as conn:
        findings = conn.execute(
            "SELECT id, rule_id, file, line, status, source_kind, run_id, repo_url, sha "
            "FROM findings ORDER BY rule_id"
        ).fetchall()
        hops = conn.execute("SELECT * FROM chain_hops").fetchall()
        span = conn.execute(
            "SELECT * FROM tool_spans WHERE run_id = ?", (seeded["run_id"],)
        ).fetchone()
        run = conn.execute(
            "SELECT * FROM runs WHERE id = ?", (seeded["run_id"],)
        ).fetchone()

    assert [r["rule_id"] for r in findings] == ["hunt.admin", "hunt.session"]
    assert {r["id"] for r in findings} == {seeded["from_id"], seeded["to_id"]}
    assert {r["status"] for r in findings} == {"done"}
    assert {r["source_kind"] for r in findings} == {"hunt"}
    assert {r["run_id"] for r in findings} == {seeded["run_id"]}
    assert len({(r["file"], r["line"]) for r in findings}) == 2
    assert {r["repo_url"] for r in findings} == {run["repo"]}
    assert {r["sha"] for r in findings} == {run["sha"]}

    assert run["engagement_id"] == seeded["engagement_id"]
    assert run["mode"] == "hunt"
    assert run["playbook"] == "web-app.v1"
    assert run["status"] == "done"
    assert run["blast_radius"] == "safe"
    assert run["scope_json"] == "{}"

    assert len(hops) == 1
    hop = hops[0]
    assert hop["id"] == seeded["hop_id"]
    assert hop["kind"] == "session"
    assert hop["from_id"] == seeded["from_id"]
    assert hop["to_id"] == seeded["to_id"]

    artifact = Path(hop["evidence_uri"])
    assert artifact.is_file()
    assert span["agent"] == "hunter"
    assert span["tool"] == "http_get"
    assert span["result_sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert artifact.name == f"{span['result_sha256']}.json"


def test_graph_route_returns_path(db_path: Path, tmp_path: Path) -> None:
    seeded = chain.seed_two_hop(db_path=db_path, transcripts_dir=tmp_path / "transcripts")

    with db.session(db_path) as conn:
        labels = {
            r["id"]: f"{r['file']}:{r['line']}"
            for r in conn.execute("SELECT id, file, line FROM findings")
        }
        evidence_uri = conn.execute(
            "SELECT evidence_uri FROM chain_hops WHERE id = ?", (seeded["hop_id"],)
        ).fetchone()["evidence_uri"]

    response = _client(db_path).get(f"/engagements/{seeded['engagement_id']}/graph")

    assert response.status_code == 200
    body = response.json()
    assert body["engagement_id"] == seeded["engagement_id"]
    assert body["nodes"] == [
        {"id": node_id, "kind": "finding", "label": labels[node_id]}
        for node_id in sorted(labels)
    ]
    assert body["hops"] == [
        {
            "id": seeded["hop_id"],
            "from_id": seeded["from_id"],
            "to_id": seeded["to_id"],
            "kind": "session",
            "evidence_uri": evidence_uri,
        }
    ]
    assert Path(evidence_uri).is_file()
    banned = {"proof", "severity", "vuln_class"}
    assert banned.isdisjoint(body)
    assert all(banned.isdisjoint(node) for node in body["nodes"])


def test_graph_lists_a_hop_reaching_in_from_another_engagement(
    db_path: Path, tmp_path: Path
) -> None:
    seeded = chain.seed_two_hop(db_path=db_path, transcripts_dir=tmp_path / "transcripts")
    landed = _seed_second_engagement(db_path)
    hop_id = chain.record_hop(
        db_path=db_path,
        from_id=seeded["to_id"],
        to_id=landed["finding_id"],
        kind="cred",
        evidence_uri="",
    )

    body = _client(db_path).get(f"/engagements/{landed['engagement_id']}/graph").json()

    assert [h["id"] for h in body["hops"]] == [hop_id]
    assert [n["id"] for n in body["nodes"]] == [landed["finding_id"]]


def test_graph_unknown_engagement_404(db_path: Path) -> None:
    response = _client(db_path).get("/engagements/nope/graph")

    assert response.status_code == 404
    assert response.json() == {"error": "not_found", "detail": "engagement not found"}


def test_graph_empty_engagement_200(db_path: Path) -> None:
    with db.session(db_path) as conn:
        conn.execute(
            "INSERT INTO engagements (id, name, org, created_at) VALUES (?, ?, ?, ?)",
            ("eng-empty", "empty", "acme", "2026-01-01T00:00:00+00:00"),
        )

    response = _client(db_path).get("/engagements/eng-empty/graph")

    assert response.status_code == 200
    assert response.json() == {
        "engagement_id": "eng-empty",
        "nodes": [],
        "hops": [],
    }


def test_record_hop_unknown_kind_raises(db_path: Path, tmp_path: Path) -> None:
    seeded = chain.seed_two_hop(db_path=db_path, transcripts_dir=tmp_path / "transcripts")

    with pytest.raises(ValueError):
        chain.record_hop(
            db_path=db_path,
            from_id=seeded["from_id"],
            to_id=seeded["to_id"],
            kind="explode",
            evidence_uri="",
        )


def test_record_hop_missing_finding_raises(db_path: Path, tmp_path: Path) -> None:
    seeded = chain.seed_two_hop(db_path=db_path, transcripts_dir=tmp_path / "transcripts")

    with pytest.raises(ValueError):
        chain.record_hop(
            db_path=db_path,
            from_id="ghost",
            to_id=seeded["to_id"],
            kind="session",
            evidence_uri="",
        )
    with pytest.raises(ValueError):
        chain.record_hop(
            db_path=db_path,
            from_id=seeded["from_id"],
            to_id="ghost",
            kind="session",
            evidence_uri="",
        )

    with db.session(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) c FROM chain_hops").fetchone()["c"] == 1


def test_no_finding_is_published(db_path: Path, tmp_path: Path) -> None:
    chain.seed_two_hop(db_path=db_path, transcripts_dir=tmp_path / "transcripts")

    with db.session(db_path) as conn:
        rows = conn.execute(
            "SELECT COUNT(*) c FROM findings WHERE status IN ('published', 'needs_review')"
        ).fetchone()
    assert rows["c"] == 0
