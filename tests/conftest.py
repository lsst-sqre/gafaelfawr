"""pytest fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import fakeredis
import pytest

if TYPE_CHECKING:
    import redis
    from typing import Iterator


@pytest.fixture
def redis_client() -> Iterator[redis.Redis]:
    """Replace Redis with a FakeRedis instance.

    Patches the uses of Redis in the code base to use the same FakeRedis
    client instead.

    Returns
    -------
    redis : `fakeredis.FakeRedis`
        The FakeRedis client that the code will also use.
    """
    redis = fakeredis.FakeRedis()
    with patch("jwt_authorizer.session.get_redis_client") as session_redis:
        with patch("jwt_authorizer.tokens.get_redis_client") as token_redis:
            session_redis.return_value = redis
            token_redis.return_value = redis
            yield redis
