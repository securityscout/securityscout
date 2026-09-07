"""Control-plane HTTP: engagement, run, findings list, replay enqueue."""

from __future__ import annotations

from pathlib import Path

from triage import db


def test_create_engagement_create_run_list_findings_replay_202(
    tmp_path: Path,
) -> None:
    from fastapi.testclient import TestClient

    from api.app import create_app

    db_path = tmp_path / "api.db"
    db.init_schema(db_path)
    client = TestClient(create_app(db_path))

    created = client.post(
        "/engagements",
        json={"name": "acme-web", "org": "acme", "policy_json": {}},
    )
    assert created.status_code == 201
    engagement = created.json()
    assert engagement["name"] == "acme-web"
    assert engagement["org"] == "acme"
    eng_id = engagement["id"]

    run_resp = client.post(
        f"/engagements/{eng_id}/runs",
        json={
            "mode": "triage",
            "playbook": "web-app.v1",
            "repo": "acme/app",
            "sha": "deadbeefcafebabedeadbeefcafebabe",
        },
    )
    assert run_resp.status_code == 201
    run = run_resp.json()
    assert run["engagement_id"] == eng_id
    assert run["mode"] == "triage"
    assert run["status"] == "queued"
    run_id = run["id"]

    with db.session(db_path) as conn:
        conn.execute(
            """
            INSERT INTO findings (
              id, repo_url, sha, rule_id, file, line, status, run_id, source_kind
            ) VALUES (?, ?, ?, ?, ?, ?, 'done', ?, 'sast_csv')
            """,
            (
                "f1",
                "https://github.com/acme/app.git",
                "deadbeefcafebabedeadbeefcafebabe",
                "rule.x",
                "src/a.py",
                1,
                run_id,
            ),
        )

    listed = client.get("/findings", params={"engagement_id": eng_id})
    assert listed.status_code == 200
    findings = listed.json()["findings"]
    assert len(findings) == 1
    assert findings[0]["id"] == "f1"
    assert findings[0]["run_id"] == run_id

    replay = client.post("/findings/f1/replay")
    assert replay.status_code == 202
    body = replay.json()
    assert body["finding_id"] == "f1"
    assert body["replay_status"] == "queued"
    assert "passed" not in body
