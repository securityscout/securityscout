# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import httpx
import pytest

from agents.approval import ApprovalContext
from agents.orchestrator import AdvisoryWorkflowState
from agents.workflow_slack_handlers import handle_patch_oracle_request, handle_preflight_review_decision
from config import AppConfig, RepoConfig, ReposManifest, Settings
from models import Finding, FindingStatus, Severity, SSVCAction, WorkflowKind, WorkflowRun
from tools.slack import SlackAPIError, SlackClient
from webhooks.slack import SlackActionId


def _app_config() -> AppConfig:
    repo = RepoConfig(
        name="demo",
        github_org="acme",
        github_repo="app",
        slack_channel="#sec",
        allowed_workflows=[],
        notify_on_severity=["high"],
        require_approval_for=["critical"],
        issue_trackers=[],
    )
    settings = MagicMock(spec=Settings)
    return AppConfig(
        settings=settings,
        repos=ReposManifest(repos=[repo]),
        repos_yaml_sha256="0" * 64,
        repos_yaml_path=Path(__file__),
    )


def _slack_client_ok() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True, "channel": "C1", "ts": "1.0"})

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_preflight_proceed_enqueues_and_moves_to_building_env(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        ssvc_action=SSVCAction.act,
        status=FindingStatus.unconfirmed,
        title="t",
        evidence={"ghsa_id": "GHSA-1234-5678-ABCD", "advisory_source": "repository"},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state=AdvisoryWorkflowState.awaiting_preflight_decision.value,
    )
    db_session.add(run)
    await db_session.commit()

    enqueue = AsyncMock(return_value="job-1")

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(
            finding_id=finding.id,
            workflow_run_id=run.id,
            repo_name="demo",
        )
        await handle_preflight_review_decision(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            action_id=SlackActionId.preflight_proceed,
            user_id="UAPPROVER",
            channel_id="C1",
            message_ts="1.2",
            enqueue_advisory=enqueue,
        )

    await db_session.refresh(run)
    assert run.state == AdvisoryWorkflowState.building_env.value
    enqueue.assert_awaited_once()


@pytest.mark.asyncio
async def test_preflight_cancel_blocks_run(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        title="t",
        evidence={"ghsa_id": "GHSA-1234-5678-ABCD"},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state=AdvisoryWorkflowState.awaiting_preflight_decision.value,
    )
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        await handle_preflight_review_decision(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            action_id=SlackActionId.preflight_cancel,
            user_id="U1",
            channel_id="C1",
            message_ts="1.2",
            enqueue_advisory=AsyncMock(),
        )

    await db_session.refresh(run)
    assert run.state == AdvisoryWorkflowState.pre_flight_blocked.value
    assert run.completed_at is not None


@pytest.mark.asyncio
async def test_patch_oracle_request_enqueues_when_eligible(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        status=FindingStatus.confirmed_low,
        title="t",
        poc_executed=True,
        patch_available=True,
        evidence={"oracle": {"patched_ref_candidates": ["1.2.0"]}},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(finding_id=finding.id, workflow_type=WorkflowKind.advisory, state="done")
    db_session.add(run)
    await db_session.commit()

    enqueue = AsyncMock()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        await handle_patch_oracle_request(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            user_id="U1",
            channel_id="C1",
            message_ts="9.9",
            enqueue_patch_oracle=enqueue,
        )

    enqueue.assert_awaited_once()


@pytest.mark.asyncio
async def test_preflight_proceed_without_ghsa_replies_error(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        title="t",
        evidence={},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state=AdvisoryWorkflowState.awaiting_preflight_decision.value,
    )
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        await handle_preflight_review_decision(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            action_id=SlackActionId.preflight_proceed,
            user_id="U1",
            channel_id="C1",
            message_ts="1.2",
            enqueue_advisory=AsyncMock(),
        )

    await db_session.refresh(run)
    assert run.state == AdvisoryWorkflowState.awaiting_preflight_decision.value


@pytest.mark.asyncio
async def test_preflight_when_not_awaiting_replies_only(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        title="t",
        evidence={"ghsa_id": "GHSA-1234-5678-ABCD"},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state=AdvisoryWorkflowState.done.value,
    )
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        await handle_preflight_review_decision(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            action_id=SlackActionId.preflight_proceed,
            user_id="U1",
            channel_id="C1",
            message_ts="1.2",
            enqueue_advisory=AsyncMock(),
        )


@pytest.mark.asyncio
async def test_patch_oracle_rejects_non_confirmed_low(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        status=FindingStatus.unconfirmed,
        title="t",
        patch_available=True,
        evidence={"oracle": {"patched_ref_candidates": ["1.0.0"]}},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(finding_id=finding.id, workflow_type=WorkflowKind.advisory, state="x")
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        await handle_patch_oracle_request(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            user_id="U1",
            channel_id="C1",
            message_ts="9.9",
            enqueue_patch_oracle=AsyncMock(),
        )


@pytest.mark.asyncio
async def test_preflight_proceed_without_queue_skips_state_change(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        title="t",
        evidence={"ghsa_id": "GHSA-1234-5678-ABCD"},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state=AdvisoryWorkflowState.awaiting_preflight_decision.value,
    )
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        await handle_preflight_review_decision(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            action_id=SlackActionId.preflight_proceed,
            user_id="U1",
            channel_id="C1",
            message_ts="1.2",
            enqueue_advisory=None,
        )

    await db_session.refresh(run)
    assert run.state == AdvisoryWorkflowState.awaiting_preflight_decision.value


@pytest.mark.asyncio
async def test_patch_oracle_without_patch_available(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        status=FindingStatus.confirmed_low,
        title="t",
        poc_executed=True,
        patch_available=False,
        evidence={"oracle": {"patched_ref_candidates": ["1"]}},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(finding_id=finding.id, workflow_type=WorkflowKind.advisory, state="x")
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        await handle_patch_oracle_request(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            user_id="U1",
            channel_id="C1",
            message_ts="9.9",
            enqueue_patch_oracle=AsyncMock(),
        )


@pytest.mark.asyncio
async def test_patch_oracle_without_oracle_metadata(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        status=FindingStatus.confirmed_low,
        title="t",
        poc_executed=True,
        patch_available=True,
        evidence={},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(finding_id=finding.id, workflow_type=WorkflowKind.advisory, state="x")
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        await handle_patch_oracle_request(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            user_id="U1",
            channel_id="C1",
            message_ts="9.9",
            enqueue_patch_oracle=AsyncMock(),
        )


@pytest.mark.asyncio
async def test_patch_oracle_without_enqueue(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        status=FindingStatus.confirmed_low,
        title="t",
        poc_executed=True,
        patch_available=True,
        evidence={"oracle": {"patched_ref_candidates": ["1.0.0"]}},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(finding_id=finding.id, workflow_type=WorkflowKind.advisory, state="x")
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        await handle_patch_oracle_request(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            user_id="U1",
            channel_id="C1",
            message_ts="9.9",
            enqueue_patch_oracle=None,
        )


@pytest.mark.asyncio
async def test_preflight_unknown_run_returns_silently(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        title="t",
        evidence={"ghsa_id": "GHSA-1234-5678-ABCD"},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state=AdvisoryWorkflowState.awaiting_preflight_decision.value,
    )
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        bad_ctx = ApprovalContext(
            finding_id=finding.id,
            workflow_run_id=uuid4(),
            repo_name="demo",
        )
        await handle_preflight_review_decision(
            db_session,
            _app_config(),
            slack,
            ctx=bad_ctx,
            action_id=SlackActionId.preflight_proceed,
            user_id="U1",
            channel_id="C1",
            message_ts="1.2",
            enqueue_advisory=AsyncMock(),
        )


@pytest.mark.asyncio
async def test_preflight_unknown_repo_returns_silently(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        title="t",
        evidence={"ghsa_id": "GHSA-1234-5678-ABCD"},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state=AdvisoryWorkflowState.awaiting_preflight_decision.value,
    )
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="missing-repo")
        await handle_preflight_review_decision(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            action_id=SlackActionId.preflight_proceed,
            user_id="U1",
            channel_id="C1",
            message_ts="1.2",
            enqueue_advisory=AsyncMock(),
        )


@pytest.mark.asyncio
async def test_preflight_thread_reply_slack_error_is_swallowed(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        title="t",
        evidence={"ghsa_id": "GHSA-1234-5678-ABCD"},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state=AdvisoryWorkflowState.done.value,
    )
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        with patch.object(
            slack,
            "post_thread_reply",
            new=AsyncMock(side_effect=SlackAPIError("x", is_transient=True)),
        ):
            await handle_preflight_review_decision(
                db_session,
                _app_config(),
                slack,
                ctx=ctx,
                action_id=SlackActionId.preflight_proceed,
                user_id="U1",
                channel_id="C1",
                message_ts="1.2",
                enqueue_advisory=AsyncMock(),
            )


@pytest.mark.asyncio
async def test_preflight_unknown_action_replies_in_thread(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        title="t",
        evidence={"ghsa_id": "GHSA-1234-5678-ABCD"},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state=AdvisoryWorkflowState.awaiting_preflight_decision.value,
    )
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        mock_reply = AsyncMock()
        with patch.object(slack, "post_thread_reply", new=mock_reply):
            await handle_preflight_review_decision(
                db_session,
                _app_config(),
                slack,
                ctx=ctx,
                action_id=SlackActionId.approve,
                user_id="U1",
                channel_id="C1",
                message_ts="1.2",
                enqueue_advisory=AsyncMock(),
            )
        mock_reply.assert_awaited_once()
        assert "Unrecognized" in (mock_reply.call_args.kwargs.get("text") or "")


@pytest.mark.asyncio
async def test_patch_oracle_missing_finding_returns_silently(db_session) -> None:
    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(
            finding_id=uuid4(),
            workflow_run_id=uuid4(),
            repo_name="demo",
        )
        await handle_patch_oracle_request(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            user_id="U1",
            channel_id="C1",
            message_ts="9.9",
            enqueue_patch_oracle=AsyncMock(),
        )


@pytest.mark.asyncio
async def test_patch_oracle_unknown_repo_returns_silently(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        status=FindingStatus.confirmed_low,
        title="t",
        poc_executed=True,
        patch_available=True,
        evidence={"oracle": {"patched_ref_candidates": ["1.0.0"]}},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(finding_id=finding.id, workflow_type=WorkflowKind.advisory, state="x")
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="nope")
        await handle_patch_oracle_request(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            user_id="U1",
            channel_id="C1",
            message_ts="9.9",
            enqueue_patch_oracle=AsyncMock(),
        )


@pytest.mark.asyncio
async def test_patch_oracle_whitespace_only_candidates_replies(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        repo_name="acme/app",
        source_ref="ref",
        severity=Severity.high,
        status=FindingStatus.confirmed_low,
        title="t",
        poc_executed=True,
        patch_available=True,
        evidence={"oracle": {"patched_ref_candidates": ["  ", ""]}},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(finding_id=finding.id, workflow_type=WorkflowKind.advisory, state="x")
    db_session.add(run)
    await db_session.commit()

    transport = _slack_client_ok()
    async with httpx.AsyncClient(base_url="https://slack.com/api", transport=transport) as http:
        slack = SlackClient("xoxb-fake", client=http)
        ctx = ApprovalContext(finding_id=finding.id, workflow_run_id=run.id, repo_name="demo")
        await handle_patch_oracle_request(
            db_session,
            _app_config(),
            slack,
            ctx=ctx,
            user_id="U1",
            channel_id="C1",
            message_ts="9.9",
            enqueue_patch_oracle=AsyncMock(),
        )
