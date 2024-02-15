"""Add oidc token type.

Revision ID: 2feb306dd1ee
Revises: d2a7f04de565
Create Date: 2024-02-09 23:10:43.229238+00:00
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2feb306dd1ee"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE tokentype ADD VALUE IF NOT EXISTS 'oidc'")


def downgrade() -> None:
    # PostgreSQL does not appear to support removing values from enums.
    pass
