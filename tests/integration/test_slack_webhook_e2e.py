# SPDX-License-Identifier: Apache-2.0
"""End-to-end integration test for the Slack webhook HTTP handler.

Exercises the full path: HTTP POST → signature verification → payload parsing →
approval handler → DB update → Slack thread reply.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlencode

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.orchestrator import AdvisoryWorkflowState
from config import (
    AppConfig,
    GovernanceApprover,
    GovernanceConfig,
    GovernanceRule,
    RepoConfig,
    ReposManifest,
    Settings,
)
from db import create_engine, create_session_factory
from models import (
    Base,
    Finding,
    FindingStatus,
    Severity,
    SSVCAction,
    WorkflowKind,
    WorkflowRun,
)
from tools.slack import ApprovalButtonContext
from webhooks.slack import SlackActionId, create_slack_webhook_router

pytestmark = pytest.mark.integration

_SIGNING_SECRET = "test-slack-signing-secret-e2e"
_BOT_TOKEN = "xoxb-test-e2e-token"


def _sign(body: bytes, secret: str = _SIGNING_SECRET) -> tuple[str, str]:
    """Produce a valid X-Slack-Signature + X-Slack-Request-Timestamp pair."""
    ts = str(int(time.time()))
    basestring = f"v0:{ts}:{body.decode()}".encode()
    sig = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    return sig, ts


def _interactive_payload(action_id: str, button_value: str, user_id: str = "U0APPROVER") -> bytes:
    payload = {
        "type": "block_actions",
        "user": {"id": user_id},
        "container": {"message_ts": "1111.2222", "channel_id": "C0SEC"},
        "channel": {"id": "C0SEC"},
        "actions": [
            {
                "action_id": action_id,
                "value": button_value,
            }
        ],
    }
    return urlencode({"payload": json.dumps(payload)}).encode("utf-8")


@pytest.fixture
async def e2e_app(tmp_path):
    """Build a minimal FastAPI app with the Slack webhook router and real SQLite."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'slack_e2e.db'}"
    engine = create_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = create_session_factory(engine)

    async with factory() as session:
        finding = Finding(
            workflow=WorkflowKind.advisory,
            repo_name="acme/app",
            source_ref="acme/app GHSA-E2E-TEST-1234",
            severity=Severity.high,
            ssvc_action=SSVCAction.act,
            status=FindingStatus.unconfirmed,
            triage_confidence=0.85,
            title="E2E test finding",
        )
        session.add(finding)
        await session.flush()

        run = WorkflowRun(
            finding_id=finding.id,
            workflow_type=WorkflowKind.advisory,
            state=AdvisoryWorkflowState.awaiting_approval.value,
        )
        session.add(run)
        await session.commit()

        f_id = finding.id
        r_id = run.id

    governance = GovernanceConfig(approve=[GovernanceRule(severity=[Severity.high])])
    repo = RepoConfig(
        name="demo",
        github_org="acme",
        github_repo="app",
        slack_channel="#security",
        allowed_workflows=[],
        notify_on_severity=["high"],
        require_approval_for=["critical"],
        issue_trackers=[],
        governance=governance,
        approvers=[GovernanceApprover(slack_user="U0APPROVER")],
    )
    settings = Settings()
    app_config = AppConfig(
        settings=settings,
        repos=ReposManifest(repos=[repo]),
        repos_yaml_sha256="0" * 64,
        repos_yaml_path=Path("/tmp/repos.yaml"),
    )

    app = FastAPI()
    app.state.settings = MagicMock(spec=Settings)
    app.state.settings.slack_signing_secret = _SIGNING_SECRET
    app.state.settings.slack_bot_token = _BOT_TOKEN
    app.state.app_config = app_config
    app.state.session_factory = factory

    app.include_router(create_slack_webhook_router())

    yield app, factory, f_id, r_id
    await engine.dispose()


class TestSlackWebhookE2E:
    @pytest.mark.asyncio
    async def test_approve_through_http_handler(self, e2e_app) -> None:
        """Full HTTP POST → 200 → DB shows approved."""
        app, factory, finding_id, run_id = e2e_app

        button_value = ApprovalButtonContext(
            finding_id=finding_id,
            workflow_run_id=run_id,
            repo_name="demo",
        ).encode()

        body = _interactive_payload(SlackActionId.approve.value, button_value)
        sig, ts = _sign(body)

        with patch("webhooks.slack.SlackClient") as mock_cls:
            mock_slack = AsyncMock()
            mock_slack.post_thread_reply = AsyncMock()
            mock_cls.return_value = mock_slack
            mock_slack.__aenter__ = AsyncMock(return_value=mock_slack)
            mock_slack.__aexit__ = AsyncMock(return_value=None)

            with TestClient(app) as client:
                resp = client.post(
                    "/webhooks/slack",
                    content=body,
                    headers={
                        "X-Slack-Signature": sig,
                        "X-Slack-Request-Timestamp": ts,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )

        assert resp.status_code == 200

        async with factory() as session:
            run = await session.get(WorkflowRun, run_id)
            finding = await session.get(Finding, finding_id)

        assert run is not None
        assert run.state == AdvisoryWorkflowState.done.value
        assert run.completed_at is not None
        assert finding is not None
        assert finding.approved_by == "U0APPROVER"
        assert finding.approved_at is not None

    @pytest.mark.asyncio
    async def test_preflight_proceed_through_http_handler(self, e2e_app) -> None:
        app, factory, finding_id, run_id = e2e_app

        async with factory() as session:
            run = await session.get(WorkflowRun, run_id)
            finding = await session.get(Finding, finding_id)
            assert run is not None
            assert finding is not None
            run.state = AdvisoryWorkflowState.awaiting_preflight_decision.value
            finding.evidence = {
                "ghsa_id": "GHSA-1234-5678-ABCD",
                "advisory_source": "repository",
            }
            await session.commit()

        enqueue = AsyncMock(return_value="job-preflight")
        app.state.enqueue_advisory = enqueue

        button_value = ApprovalButtonContext(
            finding_id=finding_id,
            workflow_run_id=run_id,
            repo_name="demo",
        ).encode()

        body = _interactive_payload(SlackActionId.preflight_proceed.value, button_value)
        sig, ts = _sign(body)

        with patch("webhooks.slack.SlackClient") as mock_cls:
            mock_slack = AsyncMock()
            mock_slack.post_thread_reply = AsyncMock()
            mock_cls.return_value = mock_slack
            mock_slack.__aenter__ = AsyncMock(return_value=mock_slack)
            mock_slack.__aexit__ = AsyncMock(return_value=None)

            with TestClient(app) as client:
                resp = client.post(
                    "/webhooks/slack",
                    content=body,
                    headers={
                        "X-Slack-Signature": sig,
                        "X-Slack-Request-Timestamp": ts,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )

        assert resp.status_code == 200
        enqueue.assert_awaited_once()

        async with factory() as session:
            run2 = await session.get(WorkflowRun, run_id)
        assert run2 is not None
        assert run2.state == AdvisoryWorkflowState.building_env.value

    @pytest.mark.asyncio
    async def test_run_patch_oracle_through_http_handler(self, e2e_app) -> None:
        app, factory, finding_id, run_id = e2e_app

        async with factory() as session:
            finding = await session.get(Finding, finding_id)
            assert finding is not None
            finding.status = FindingStatus.confirmed_low
            finding.poc_executed = True
            finding.patch_available = True
            finding.evidence = {"oracle": {"patched_ref_candidates": ["1.0.0"]}}
            await session.commit()

        enqueue_po = AsyncMock(return_value="job-oracle")
        app.state.enqueue_patch_oracle = enqueue_po

        button_value = ApprovalButtonContext(
            finding_id=finding_id,
            workflow_run_id=run_id,
            repo_name="demo",
        ).encode()
        body = _interactive_payload(SlackActionId.run_patch_oracle.value, button_value)
        sig, ts = _sign(body)

        with patch("webhooks.slack.SlackClient") as mock_cls:
            mock_slack = AsyncMock()
            mock_slack.post_thread_reply = AsyncMock()
            mock_cls.return_value = mock_slack
            mock_slack.__aenter__ = AsyncMock(return_value=mock_slack)
            mock_slack.__aexit__ = AsyncMock(return_value=None)

            with TestClient(app) as client:
                resp = client.post(
                    "/webhooks/slack",
                    content=body,
                    headers={
                        "X-Slack-Signature": sig,
                        "X-Slack-Request-Timestamp": ts,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )

        assert resp.status_code == 200
        enqueue_po.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_reject_through_http_handler(self, e2e_app) -> None:
        """Reject action → finding marked false_positive."""
        app, factory, finding_id, run_id = e2e_app

        button_value = ApprovalButtonContext(
            finding_id=finding_id,
            workflow_run_id=run_id,
            repo_name="demo",
        ).encode()

        body = _interactive_payload(SlackActionId.reject.value, button_value)
        sig, ts = _sign(body)

        with patch("webhooks.slack.SlackClient") as mock_cls:
            mock_slack = AsyncMock()
            mock_slack.post_thread_reply = AsyncMock()
            mock_cls.return_value = mock_slack
            mock_slack.__aenter__ = AsyncMock(return_value=mock_slack)
            mock_slack.__aexit__ = AsyncMock(return_value=None)

            with TestClient(app) as client:
                resp = client.post(
                    "/webhooks/slack",
                    content=body,
                    headers={
                        "X-Slack-Signature": sig,
                        "X-Slack-Request-Timestamp": ts,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )

        assert resp.status_code == 200

        async with factory() as session:
            finding = await session.get(Finding, finding_id)

        assert finding is not None
        assert finding.status == FindingStatus.false_positive

    @pytest.mark.asyncio
    async def test_invalid_signature_returns_401(self, e2e_app) -> None:
        app, *_ = e2e_app
        body = _interactive_payload(SlackActionId.approve.value, "dummy")
        _, ts = _sign(body)

        with TestClient(app) as client:
            resp = client.post(
                "/webhooks/slack",
                content=body,
                headers={
                    "X-Slack-Signature": "v0=badbadbadbad",
                    "X-Slack-Request-Timestamp": ts,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_stale_timestamp_returns_401(self, e2e_app) -> None:
        app, *_ = e2e_app
        body = _interactive_payload(SlackActionId.approve.value, "dummy")
        stale_ts = str(int(time.time()) - 600)
        basestring = f"v0:{stale_ts}:{body.decode()}".encode()
        sig = "v0=" + hmac.new(_SIGNING_SECRET.encode(), basestring, hashlib.sha256).hexdigest()

        with TestClient(app) as client:
            resp = client.post(
                "/webhooks/slack",
                content=body,
                headers={
                    "X-Slack-Signature": sig,
                    "X-Slack-Request-Timestamp": stale_ts,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_malformed_payload_returns_400(self, e2e_app) -> None:
        app, *_ = e2e_app
        body = b"not-a-valid-payload"
        sig, ts = _sign(body)

        with TestClient(app) as client:
            resp = client.post(
                "/webhooks/slack",
                content=body,
                headers={
                    "X-Slack-Signature": sig,
                    "X-Slack-Request-Timestamp": ts,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

        assert resp.status_code == 400
