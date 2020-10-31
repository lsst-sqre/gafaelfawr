"""Tests for the ``/auth/api/v1/users/*/tokens`` and related routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest

from gafaelfawr.models.token import TokenGroup

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_token_info(setup: SetupTest) -> None:
    created = datetime.now(tz=timezone.utc).replace(microsecond=0)
    expires = created + timedelta(days=1)
    token = await setup.add_session_token(
        username="example",
        scopes=["read:all"],
        created=created,
        expires=expires,
        name="Example Person",
        uid=45613,
        groups=[TokenGroup(name="foo", id=12313)],
    )

    r = await setup.client.get(
        "/auth/api/v1/token-info", headers={"Authorization": f"bearer {token}"}
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "example",
        "token_type": "session",
        "scopes": ["read:all"],
        "created": int(created.timestamp()),
        "expires": int(expires.timestamp()),
    }

    r = await setup.client.get(
        "/auth/api/v1/user-info", headers={"Authorization": f"bearer {token}"}
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "example",
        "name": "Example Person",
        "uid": 45613,
        "groups": [
            {
                "name": "foo",
                "id": 12313,
            }
        ],
    }
