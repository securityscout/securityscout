"""add ux_findings_advisory_ghsa unique partial index

Revision ID: f1e2d3c4b5a6
Revises: e8a1c2d3f4b5
Create Date: 2026-04-27

"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f1e2d3c4b5a6"
down_revision: str | None = "e8a1c2d3f4b5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_log = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        _log.info(
            "Skipping ux_findings_advisory_ghsa: dialect is %s (unique partial index applies on PostgreSQL only).",
            bind.dialect.name,
        )
        return
    op.execute(
        sa.text(
            """
            CREATE UNIQUE INDEX ux_findings_advisory_ghsa
            ON findings (repo_name, (evidence->>'ghsa_id'))
            WHERE workflow = 'advisory'
            """
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        _log.info(
            "Skipping drop ux_findings_advisory_ghsa: dialect is %s (index exists on PostgreSQL only).",
            bind.dialect.name,
        )
        return
    op.execute(sa.text("DROP INDEX IF EXISTS ux_findings_advisory_ghsa"))
