# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from agents.env_builder import DetectedStack, EnvBuildResult
from agents.patch_oracle import _truncate_log, run_patch_oracle_job
from agents.sandbox_executor import ExecutionResult, PocType
from exceptions import PermanentError
from models import Finding, FindingStatus, Severity, SSVCAction, WorkflowKind, WorkflowRun
from tools.docker_sandbox import SandboxBuildError


def test_truncate_log_none_and_short_and_long() -> None:
    assert _truncate_log(None) is None
    assert _truncate_log("ok") == "ok"
    long = "x" * 600
    out = _truncate_log(long, max_chars=500)
    assert out is not None
    assert len(out) == 500
    assert out.endswith("…")


@pytest.mark.asyncio
async def test_run_patch_oracle_upgrades_when_differential_holds(db_session, mocker, tmp_path: Path) -> None:
    repo_a = tmp_path / "a"
    repo_b = tmp_path / "b"
    repo_a.mkdir()
    repo_b.mkdir()

    finding = Finding(
        workflow=WorkflowKind.advisory,
        source_ref="https://github.com/advisories/GHSA-1111-2222-3333",
        severity=Severity.high,
        ssvc_action=SSVCAction.act,
        status=FindingStatus.confirmed_low,
        triage_confidence=0.9,
        title="oracle test",
        reproduction="print(1)",
        poc_executed=True,
        patch_available=True,
        evidence={
            "oracle": {"vulnerable_ref": "main", "patched_ref_candidates": ["v2.0.0"]},
            "execution": {"poc_type": PocType.RESEARCHER_SUBMITTED.value},
        },
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state="awaiting_approval",
    )
    db_session.add(run)
    await db_session.commit()

    builds = [
        EnvBuildResult(
            image_tag="img-vuln",
            repo_path=repo_a,
            detected_stack=DetectedStack.PYTHON,
            build_log="",
        ),
        EnvBuildResult(
            image_tag="img-pat",
            repo_path=repo_b,
            detected_stack=DetectedStack.PYTHON,
            build_log="",
        ),
    ]
    mocker.patch("agents.patch_oracle.build_environment", side_effect=builds)

    vuln_exec = ExecutionResult(
        confidence_tier=FindingStatus.confirmed_low,
        evidence_excerpt="vuln",
        raw_stdout="exploitable confirmed",
        raw_stderr="",
        elapsed_seconds=1.0,
        poc_type=PocType.RESEARCHER_SUBMITTED,
        exit_code=0,
    )
    pat_exec = ExecutionResult(
        confidence_tier=FindingStatus.unconfirmed,
        evidence_excerpt="pat",
        raw_stdout="no exploitation here",
        raw_stderr="",
        elapsed_seconds=1.0,
        poc_type=PocType.RESEARCHER_SUBMITTED,
        exit_code=0,
    )
    mocker.patch("agents.patch_oracle.execute_poc", side_effect=[vuln_exec, pat_exec])

    scm = MagicMock()
    await run_patch_oracle_job(
        db_session,
        scm,
        repo_slug="acme/app",
        finding_id=finding.id,
        workflow_run_id=run.id,
        container_socket="unix:///var/run/docker.sock",
    )

    await db_session.refresh(finding)
    assert finding.status == FindingStatus.confirmed_high
    po = (finding.evidence or {}).get("patch_oracle")
    assert isinstance(po, dict)
    assert po.get("oracle_passed") is True


@pytest.mark.asyncio
async def test_run_patch_oracle_rejects_wrong_status(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        source_ref="https://github.com/advisories/GHSA-X",
        severity=Severity.high,
        status=FindingStatus.unconfirmed,
        title="t",
        evidence={
            "oracle": {"vulnerable_ref": "main", "patched_ref_candidates": ["1"]},
        },
        patch_available=True,
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(finding_id=finding.id, workflow_type=WorkflowKind.advisory, state="x")
    db_session.add(run)
    await db_session.commit()

    with pytest.raises(RuntimeError, match="confirmed_low"):
        await run_patch_oracle_job(
            db_session,
            MagicMock(),
            repo_slug="o/r",
            finding_id=finding.id,
            workflow_run_id=run.id,
            container_socket="unix:///var/run/docker.sock",
        )


@pytest.mark.asyncio
async def test_run_patch_oracle_requires_patched_candidates(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        source_ref="ref",
        severity=Severity.high,
        status=FindingStatus.confirmed_low,
        title="t",
        poc_executed=True,
        patch_available=True,
        evidence={"oracle": {"vulnerable_ref": "main", "patched_ref_candidates": []}},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(finding_id=finding.id, workflow_type=WorkflowKind.advisory, state="x")
    db_session.add(run)
    await db_session.commit()

    with pytest.raises(RuntimeError, match="patched ref"):
        await run_patch_oracle_job(
            db_session,
            MagicMock(),
            repo_slug="o/r",
            finding_id=finding.id,
            workflow_run_id=run.id,
            container_socket="unix:///var/run/docker.sock",
        )


@pytest.mark.asyncio
async def test_run_patch_oracle_rejects_run_finding_mismatch(db_session) -> None:
    f1 = Finding(
        workflow=WorkflowKind.advisory,
        source_ref="r1",
        severity=Severity.high,
        status=FindingStatus.confirmed_low,
        title="a",
        poc_executed=True,
        patch_available=True,
        evidence={"oracle": {"patched_ref_candidates": ["1"]}},
    )
    f2 = Finding(
        workflow=WorkflowKind.advisory,
        source_ref="r2",
        severity=Severity.high,
        status=FindingStatus.confirmed_low,
        title="b",
        poc_executed=True,
        patch_available=True,
        evidence={"oracle": {"patched_ref_candidates": ["1"]}},
    )
    db_session.add(f1)
    db_session.add(f2)
    await db_session.flush()
    run = WorkflowRun(finding_id=f2.id, workflow_type=WorkflowKind.advisory, state="x")
    db_session.add(run)
    await db_session.commit()

    with pytest.raises(RuntimeError, match="does not match"):
        await run_patch_oracle_job(
            db_session,
            MagicMock(),
            repo_slug="o/r",
            finding_id=f1.id,
            workflow_run_id=run.id,
            container_socket="unix:///var/run/docker.sock",
        )


@pytest.mark.asyncio
async def test_run_patch_oracle_finding_not_found(db_session) -> None:
    fid = uuid4()
    rid = uuid4()
    with pytest.raises(RuntimeError, match="finding not found"):
        await run_patch_oracle_job(
            db_session,
            MagicMock(),
            repo_slug="o/r",
            finding_id=fid,
            workflow_run_id=rid,
            container_socket="unix:///var/run/docker.sock",
        )


@pytest.mark.asyncio
async def test_run_patch_oracle_run_not_found(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        source_ref="r",
        severity=Severity.high,
        status=FindingStatus.confirmed_low,
        title="t",
        poc_executed=True,
        patch_available=True,
        evidence={"oracle": {"patched_ref_candidates": ["1"]}},
    )
    db_session.add(finding)
    await db_session.commit()

    with pytest.raises(RuntimeError, match="workflow run not found"):
        await run_patch_oracle_job(
            db_session,
            MagicMock(),
            repo_slug="o/r",
            finding_id=finding.id,
            workflow_run_id=uuid4(),
            container_socket="unix:///var/run/docker.sock",
        )


@pytest.mark.asyncio
async def test_run_patch_oracle_requires_patch_available_flag(db_session) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        source_ref="r",
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

    with pytest.raises(RuntimeError, match="patch_available"):
        await run_patch_oracle_job(
            db_session,
            MagicMock(),
            repo_slug="o/r",
            finding_id=finding.id,
            workflow_run_id=run.id,
            container_socket="unix:///var/run/docker.sock",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("default_git_ref", "expected_first_ref"),
    [("main", "main"), ("master", "master")],
)
async def test_run_patch_oracle_defaults_vulnerable_ref_to_default_git_ref(
    db_session, mocker, default_git_ref: str, expected_first_ref: str
) -> None:
    finding = Finding(
        workflow=WorkflowKind.advisory,
        source_ref="ref",
        severity=Severity.high,
        ssvc_action=SSVCAction.act,
        status=FindingStatus.confirmed_low,
        title="t",
        reproduction="print(1)",
        poc_executed=True,
        patch_available=True,
        evidence={"oracle": {"patched_ref_candidates": ["v2"]}},
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(finding_id=finding.id, workflow_type=WorkflowKind.advisory, state="x")
    db_session.add(run)
    await db_session.commit()

    refs_seen: list[str] = []

    async def capture_build(
        _scm: MagicMock,
        *,
        repo_slug: str,
        ref: str,
        work_dir: Path,
        container_socket: str = "unix:///var/run/docker.sock",
    ) -> EnvBuildResult:
        refs_seen.append(ref)
        repo_path = work_dir / "repo"
        repo_path.mkdir(parents=True, exist_ok=True)
        return EnvBuildResult(
            image_tag="img",
            repo_path=repo_path,
            detected_stack=DetectedStack.PYTHON,
            build_log="",
        )

    mocker.patch("agents.patch_oracle.build_environment", side_effect=capture_build)
    noop = ExecutionResult(
        confidence_tier=FindingStatus.unconfirmed,
        evidence_excerpt="",
        raw_stdout="",
        raw_stderr="",
        elapsed_seconds=1.0,
        poc_type=PocType.RESEARCHER_SUBMITTED,
        exit_code=1,
    )
    mocker.patch("agents.patch_oracle.execute_poc", return_value=noop)

    await run_patch_oracle_job(
        db_session,
        MagicMock(),
        repo_slug="o/r",
        finding_id=finding.id,
        workflow_run_id=run.id,
        container_socket="unix:///var/run/docker.sock",
        default_git_ref=default_git_ref,
    )
    assert refs_seen == [expected_first_ref, "v2"]


@pytest.mark.asyncio
async def test_run_patch_oracle_tries_next_patched_candidate_when_clone_fails(
    db_session, mocker, tmp_path: Path
) -> None:
    repo_a = tmp_path / "a"
    repo_b = tmp_path / "b"
    repo_a.mkdir()
    repo_b.mkdir()

    finding = Finding(
        workflow=WorkflowKind.advisory,
        source_ref="https://github.com/advisories/GHSA-1111-2222-3333",
        severity=Severity.high,
        ssvc_action=SSVCAction.act,
        status=FindingStatus.confirmed_low,
        triage_confidence=0.9,
        title="oracle fallback",
        reproduction="print(1)",
        poc_executed=True,
        patch_available=True,
        evidence={
            "oracle": {
                "vulnerable_ref": "main",
                "patched_ref_candidates": ["nonexistent-tag", "v2.0.0"],
            },
            "execution": {"poc_type": PocType.RESEARCHER_SUBMITTED.value},
        },
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state="awaiting_approval",
    )
    db_session.add(run)
    await db_session.commit()

    builds = [
        EnvBuildResult(
            image_tag="img-vuln",
            repo_path=repo_a,
            detected_stack=DetectedStack.PYTHON,
            build_log="",
        ),
        PermanentError("no matching ref"),
        EnvBuildResult(
            image_tag="img-pat",
            repo_path=repo_b,
            detected_stack=DetectedStack.PYTHON,
            build_log="",
        ),
    ]
    mocker.patch("agents.patch_oracle.build_environment", side_effect=builds)

    vuln_exec = ExecutionResult(
        confidence_tier=FindingStatus.confirmed_low,
        evidence_excerpt="vuln",
        raw_stdout="exploitable confirmed",
        raw_stderr="",
        elapsed_seconds=1.0,
        poc_type=PocType.RESEARCHER_SUBMITTED,
        exit_code=0,
    )
    pat_exec = ExecutionResult(
        confidence_tier=FindingStatus.unconfirmed,
        evidence_excerpt="pat",
        raw_stdout="no exploitation here",
        raw_stderr="",
        elapsed_seconds=1.0,
        poc_type=PocType.RESEARCHER_SUBMITTED,
        exit_code=0,
    )
    mocker.patch("agents.patch_oracle.execute_poc", side_effect=[vuln_exec, pat_exec])

    scm = MagicMock()
    await run_patch_oracle_job(
        db_session,
        scm,
        repo_slug="acme/app",
        finding_id=finding.id,
        workflow_run_id=run.id,
        container_socket="unix:///var/run/docker.sock",
    )

    await db_session.refresh(finding)
    po = (finding.evidence or {}).get("patch_oracle")
    assert isinstance(po, dict)
    assert po.get("patched_ref") == "v2.0.0"


@pytest.mark.asyncio
async def test_run_patch_oracle_tries_next_patched_candidate_when_image_build_fails(
    db_session, mocker, tmp_path: Path
) -> None:
    repo_a = tmp_path / "a"
    repo_b = tmp_path / "b"
    repo_a.mkdir()
    repo_b.mkdir()

    finding = Finding(
        workflow=WorkflowKind.advisory,
        source_ref="https://github.com/advisories/GHSA-1111-2222-3333",
        severity=Severity.high,
        ssvc_action=SSVCAction.act,
        status=FindingStatus.confirmed_low,
        triage_confidence=0.9,
        title="oracle build fallback",
        reproduction="print(1)",
        poc_executed=True,
        patch_available=True,
        evidence={
            "oracle": {
                "vulnerable_ref": "main",
                "patched_ref_candidates": ["bad-dockerfile-tag", "v2.0.0"],
            },
            "execution": {"poc_type": PocType.RESEARCHER_SUBMITTED.value},
        },
    )
    db_session.add(finding)
    await db_session.flush()
    run = WorkflowRun(
        finding_id=finding.id,
        workflow_type=WorkflowKind.advisory,
        state="awaiting_approval",
    )
    db_session.add(run)
    await db_session.commit()

    builds = [
        EnvBuildResult(
            image_tag="img-vuln",
            repo_path=repo_a,
            detected_stack=DetectedStack.PYTHON,
            build_log="",
        ),
        SandboxBuildError("image build failed for bad tag"),
        EnvBuildResult(
            image_tag="img-pat",
            repo_path=repo_b,
            detected_stack=DetectedStack.PYTHON,
            build_log="",
        ),
    ]
    mocker.patch("agents.patch_oracle.build_environment", side_effect=builds)

    vuln_exec = ExecutionResult(
        confidence_tier=FindingStatus.confirmed_low,
        evidence_excerpt="vuln",
        raw_stdout="exploitable confirmed",
        raw_stderr="",
        elapsed_seconds=1.0,
        poc_type=PocType.RESEARCHER_SUBMITTED,
        exit_code=0,
    )
    pat_exec = ExecutionResult(
        confidence_tier=FindingStatus.unconfirmed,
        evidence_excerpt="pat",
        raw_stdout="no exploitation here",
        raw_stderr="",
        elapsed_seconds=1.0,
        poc_type=PocType.RESEARCHER_SUBMITTED,
        exit_code=0,
    )
    mocker.patch("agents.patch_oracle.execute_poc", side_effect=[vuln_exec, pat_exec])

    await run_patch_oracle_job(
        db_session,
        MagicMock(),
        repo_slug="acme/app",
        finding_id=finding.id,
        workflow_run_id=run.id,
        container_socket="unix:///var/run/docker.sock",
    )

    await db_session.refresh(finding)
    po = (finding.evidence or {}).get("patch_oracle")
    assert isinstance(po, dict)
    assert po.get("patched_ref") == "v2.0.0"
