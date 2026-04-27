# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from tools.source_ref_repo import github_owner_repo_slug_from_source_ref


def test_github_owner_repo_slug_from_repository_advisory_url() -> None:
    assert (
        github_owner_repo_slug_from_source_ref(
            "https://github.com/acme/widget/security/advisories/GHSA-aaaa-bbbb-cccc",
        )
        == "acme/widget"
    )


def test_github_owner_repo_slug_from_source_ref_case_insensitive_scheme() -> None:
    assert (
        github_owner_repo_slug_from_source_ref(
            "HTTPS://GITHUB.COM/Acme/Widget/security/advisories/GHSA-1",
        )
        == "acme/widget"
    )


def test_github_owner_repo_slug_returns_none_for_global_advisory_url() -> None:
    assert github_owner_repo_slug_from_source_ref("https://github.com/advisories/GHSA-aaaa-bbbb-cccc") is None


def test_github_owner_repo_slug_returns_none_for_non_github() -> None:
    assert github_owner_repo_slug_from_source_ref("https://example.com/a/b") is None
