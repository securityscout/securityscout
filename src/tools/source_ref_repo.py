# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re

_GITHUB_REPO_ADVISORY_PREFIX = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/security/advisories/",
    re.IGNORECASE,
)


def github_owner_repo_slug_from_source_ref(source_ref: str) -> str | None:
    """Return canonical lowercase ``owner/repo`` when *source_ref* is a repository security advisory URL."""
    m = _GITHUB_REPO_ADVISORY_PREFIX.match((source_ref or "").strip())
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}".lower()
