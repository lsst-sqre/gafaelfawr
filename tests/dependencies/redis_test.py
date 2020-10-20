"""Tests for the redis dependency."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import call, patch

from gafaelfawr.dependencies import config, redis
from tests.support.app import build_config, store_secret

if TYPE_CHECKING:
    from pathlib import Path


async def test_redis_password(tmp_path: Path) -> None:
    redis_password_file = store_secret(tmp_path, "redis", b"some-password")
    config_path = build_config(
        tmp_path,
        environment="github",
        redis_password_file=str(redis_password_file),
    )
    config.set_config_path(str(config_path))

    with patch("gafaelfawr.dependencies.create_redis_pool") as mock_create:
        redis.use_mock(False)
        await redis(config())
        assert mock_create.call_args_list == [
            call("dummy", password="some-password")
        ]
