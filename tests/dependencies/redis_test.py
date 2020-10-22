"""Tests for the redis dependency."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import call, patch

import pytest

from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.redis import redis_dependency
from tests.support.settings import build_settings, store_secret

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.asyncio
async def test_redis_password(tmp_path: Path) -> None:
    redis_password_file = store_secret(tmp_path, "redis", b"some-password")
    config_path = build_settings(
        tmp_path, "github", redis_password_file=str(redis_password_file)
    )
    config_dependency.set_config_path(str(config_path))

    function = "gafaelfawr.dependencies.redis.create_redis_pool"
    with patch(function) as mock_create:
        redis_dependency.is_mocked = False
        await redis_dependency(config_dependency())
        assert mock_create.call_args_list == [
            call("dummy", password="some-password")
        ]
        redis_dependency.redis = None
