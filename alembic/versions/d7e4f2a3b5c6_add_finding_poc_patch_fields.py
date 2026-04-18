"""add finding patch_available and poc_executed fields

Revision ID: d7e4f2a3b5c6
Revises: c5f2a1d8e930
Create Date: 2026-04-18

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d7e4f2a3b5c6"
down_revision: str | None = "c5f2a1d8e930"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("patch_available", sa.Boolean(), nullable=True))
    op.add_column("findings", sa.Column("poc_executed", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "poc_executed")
    op.drop_column("findings", "patch_available")
