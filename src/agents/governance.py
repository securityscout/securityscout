# SPDX-License-Identifier: Apache-2.0
"""Governance routing: maps a triaged finding to an auto_resolve / notify / approve tier.

Pure logic, no I/O. Precedence is approve > notify > auto_resolve (most restrictive wins) so
an ``auto_resolve`` rule matching a critical finding never suppresses an ``approve`` rule that
also matches. Default behaviour (no ``governance`` block configured) preserves strict
approval for anything above informational severity.
"""

from __future__ import annotations

from enum import StrEnum

from config import GovernanceConfig, GovernanceRule
from models import Finding, KnownStatus, Severity

__all__ = ["GovernanceTier", "decide_governance_tier"]


class GovernanceTier(StrEnum):
    auto_resolve = "auto_resolve"
    notify = "notify"
    approve = "approve"


def _default_tier(finding: Finding) -> GovernanceTier:
    if finding.severity == Severity.informational:
        return GovernanceTier.auto_resolve
    return GovernanceTier.approve


def _rule_matches(rule: GovernanceRule, finding: Finding) -> bool:
    if rule.severity is not None and finding.severity not in rule.severity:
        return False
    if rule.ssvc_action is not None and (finding.ssvc_action is None or finding.ssvc_action not in rule.ssvc_action):
        return False
    if rule.duplicate is not None:
        is_dup = finding.known_status == KnownStatus.duplicate
        if rule.duplicate != is_dup:
            return False
    if rule.patch_available is not None and (
        finding.patch_available is None or finding.patch_available != rule.patch_available
    ):
        return False
    return not (
        rule.poc_execution is not None and (finding.poc_executed is None or finding.poc_executed != rule.poc_execution)
    )


def decide_governance_tier(
    finding: Finding,
    governance: GovernanceConfig | None,
) -> GovernanceTier:
    if governance is None:
        return _default_tier(finding)
    if any(_rule_matches(r, finding) for r in governance.approve):
        return GovernanceTier.approve
    if any(_rule_matches(r, finding) for r in governance.notify):
        return GovernanceTier.notify
    if any(_rule_matches(r, finding) for r in governance.auto_resolve):
        return GovernanceTier.auto_resolve
    return _default_tier(finding)
