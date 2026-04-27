"""add finding.repo_name and workflow_runs.repo_name

Revision ID: e8a1c2d3f4b5
Revises: d7e4f2a3b5c6
Create Date: 2026-04-27

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy import text

from alembic import op
from tools.source_ref_repo import github_owner_repo_slug_from_source_ref

revision: str = "e8a1c2d3f4b5"
down_revision: str | None = "d7e4f2a3b5c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UNKNOWN_SLUG = "unknown/unknown"


def upgrade() -> None:
    op.add_column("workflow_runs", sa.Column("repo_name", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("repo_name", sa.String(length=255), nullable=True))

    conn = op.get_bind()
    rows = conn.execute(text("SELECT id, source_ref FROM findings")).fetchall()
    for row in rows:
        fid = row[0]
        ref = row[1]
        slug = github_owner_repo_slug_from_source_ref(ref if isinstance(ref, str) else "")
        if slug:
            conn.execute(
                sa.text("UPDATE findings SET repo_name = :slug WHERE id = :id"),
                {"slug": slug, "id": fid},
            )

    conn.execute(
        text("""
            UPDATE findings
            SET repo_name = (
                SELECT wr.repo_name
                FROM workflow_runs wr
                WHERE wr.finding_id = findings.id
                  AND wr.repo_name IS NOT NULL
                ORDER BY wr.started_at DESC
                LIMIT 1
            )
            WHERE repo_name IS NULL
        """),
    )

    conn.execute(
        sa.text("UPDATE findings SET repo_name = :u WHERE repo_name IS NULL"),
        {"u": _UNKNOWN_SLUG},
    )

    conn.execute(
        text("""
            UPDATE workflow_runs
            SET repo_name = (
                SELECT f.repo_name FROM findings f
                WHERE f.id = workflow_runs.finding_id
            )
            WHERE finding_id IS NOT NULL
        """),
    )

    op.create_index(op.f("ix_findings_repo_name"), "findings", ["repo_name"], unique=False)
    with op.batch_alter_table("findings") as batch_op:
        batch_op.alter_column("repo_name", existing_type=sa.String(length=255), nullable=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_repo_name"), table_name="findings")
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("repo_name")
    op.drop_column("workflow_runs", "repo_name")
