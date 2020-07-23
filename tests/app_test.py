"""Tests for create_app."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import call, patch

import aioredis
from cryptography.fernet import Fernet

from gafaelfawr.app import create_app
from gafaelfawr.keypair import RSAKeyPair
from tests.support.app import build_settings, store_secret


async def test_redis_password(tmp_path: Path) -> None:
    session_secret = Fernet.generate_key()
    session_secret_file = store_secret(tmp_path, "session", session_secret)
    issuer_key = RSAKeyPair.generate().private_key_as_pem()
    issuer_key_file = store_secret(tmp_path, "issuer", issuer_key)
    github_secret_file = store_secret(tmp_path, "github", b"github-secret")
    redis_password_file = store_secret(tmp_path, "redis", b"some-password")

    settings_path = build_settings(
        tmp_path,
        "redis-password",
        session_secret_file=session_secret_file,
        issuer_key_file=issuer_key_file,
        github_secret_file=github_secret_file,
        redis_password_file=redis_password_file,
    )

    with patch.object(aioredis, "create_redis_pool") as mock_create_pool:
        await create_app(str(settings_path))
        assert mock_create_pool.call_args_list == [
            call("dummy", password="some-password")
        ]
