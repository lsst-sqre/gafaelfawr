"""Tests for the redis dependency."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import call, patch

import pytest
from aioredis import Redis

from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.redis import redis_dependency
from tests.support.settings import build_settings, store_secret

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.asyncio
async def test_redis_password(tmp_path: Path) -> None:
    redis_password_file = store_secret(tmp_path, "redis", b"some-password")
    settings_path = build_settings(
        tmp_path, "github", redis_password_file=str(redis_password_file)
    )
    config_dependency.set_settings_path(str(settings_path))

    with patch.object(Redis, "from_url") as mock_from_url:
        redis_dependency.redis = None
        await redis_dependency(config_dependency())
        assert mock_from_url.call_args_list == [
            call("redis://localhost:6379/0", password="some-password")
        ]
        redis_dependency.redis = None
