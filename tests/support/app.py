"""Create and configure the test aiohttp application."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import mockaioredis
from cryptography.fernet import Fernet

from gafaelfawr.app import create_app
from gafaelfawr.keypair import RSAKeyPair

if TYPE_CHECKING:
    from typing import Any

    from aiohttp import web

__all__ = ["create_test_app"]


def build_settings(tmp_path: Path, template_name: str, **kwargs: Path) -> Path:
    """Construct a configuration file from a format template.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        The root of the temporary area.
    template_name : `str`
        Name of the configuration template to use.
    **kwargs : `str`
        The values to substitute into the template.

    Returns
    -------
    settings_path : `pathlib.Path`
        The path to the newly-constructed configuration file.
    """
    template_file = template_name + ".yaml.in"
    template_path = Path(__file__).parent.parent / "settings" / template_file
    with template_path.open("r") as f:
        template = f.read()
    settings = template.format(**kwargs)
    settings_path = tmp_path / "gafaelfawr.yaml"
    with settings_path.open("w") as f:
        f.write(settings)
    return settings_path


def store_secret(tmp_path: Path, name: str, secret: bytes) -> Path:
    """Store a secret in a temporary path.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        The root of the temporary area.
    name : `str`
        The name of the secret to construct nice file names.
    secret : `bytes`
        The value of the secret.
    """
    secret_path = tmp_path / name
    with secret_path.open(mode="wb") as f:
        f.write(secret)
    return secret_path


async def create_test_app(
    tmp_path: Path, *, environment: str = "github", **settings: Any
) -> web.Application:
    """Configured aiohttp Application for testing.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        Temporary directory in which to store secrets.
    environment : `str`, optional
        Settings template to use.
    **settings : Any
        Settings that override settings read from the configuration file.

    Returns
    -------
    app : `aiohttp.web.Application`
        The configured test application.
    """
    session_secret = Fernet.generate_key()
    session_secret_file = store_secret(tmp_path, "session", session_secret)
    issuer_key = RSAKeyPair.generate().private_key_as_pem()
    issuer_key_file = store_secret(tmp_path, "issuer", issuer_key)
    github_secret_file = store_secret(tmp_path, "github", b"github-secret")
    oidc_secret_file = store_secret(tmp_path, "oidc", b"oidc-secret")

    settings_path = build_settings(
        tmp_path,
        environment,
        session_secret_file=session_secret_file,
        issuer_key_file=issuer_key_file,
        github_secret_file=github_secret_file,
        oidc_secret_file=oidc_secret_file,
    )
    app = await create_app(
        settings_path=str(settings_path),
        redis_pool=await mockaioredis.create_redis_pool(""),
        **settings,
    )

    return app
