"""The oidc_clients database table."""

from datetime import datetime

from sqlalchemy import Index
from sqlalchemy.orm import Mapped, mapped_column

from ._base import SchemaBase

__all__ = ["OIDCClient"]


class OIDCClient(SchemaBase):
    """Metadata for an OpenID Connect client."""

    __tablename__ = "oidc_client"

    client_id: Mapped[str] = mapped_column(primary_key=True)
    client_secret_hash: Mapped[bytes]
    return_uri: Mapped[str]
    description: Mapped[str]
    notes: Mapped[str | None]
    created: Mapped[datetime]
    last_modified: Mapped[datetime]
    last_modified_by: Mapped[str]

    __table_args__ = (Index("oidc_client_by_client_id", "client_id"),)
