"""Test configuration parsing."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from cryptography.fernet import Fernet
from pydantic import SecretStr, ValidationError

from gafaelfawr.config import Config, OIDCConfig
from gafaelfawr.models.token import Token

from .support.config import config_path


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up environment variables that provide secrets."""
    session_secret = Fernet.generate_key().decode()
    postgres_url = "postgresql://gafaelfawr@localhost/gafaelfawr"
    redis_persistent_url = "redis://localhost/0"
    monkeypatch.setenv("GAFAELFAWR_BOOTSTRAP_TOKEN", str(Token()))
    monkeypatch.setenv("GAFAELFAWR_DATABASE_PASSWORD", "password")
    monkeypatch.setenv("GAFAELFAWR_DATABASE_URL", postgres_url)
    monkeypatch.setenv("GAFAELFAWR_GITHUB_CLIENT_SECRET", "github-secret")
    monkeypatch.setenv("GAFAELFAWR_REDIS_EPHEMERAL_URL", "redis://localhost/1")
    monkeypatch.setenv("GAFAELFAWR_REDIS_PASSWORD", "password")
    monkeypatch.setenv("GAFAELFAWR_REDIS_PERSISTENT_URL", redis_persistent_url)
    monkeypatch.setenv("GAFAELFAWR_SESSION_SECRET", session_secret)


def parse_config(path: Path) -> Config:
    """Parse the configuration file and see if any exceptions are thrown.

    Parameters
    ----------
    path
        The path to the configuration file to test.
    """
    with path.open("r") as f:
        return Config.model_validate(yaml.safe_load(f))


def test_config_alembic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Check the configuration used for Alembic operations."""
    monkeypatch.delenv("GAFAELFAWR_BOOTSTRAP_TOKEN")
    monkeypatch.delenv("GAFAELFAWR_GITHUB_CLIENT_SECRET")
    monkeypatch.delenv("GAFAELFAWR_SESSION_SECRET")
    path = Path(__file__).parent.parent / "alembic" / "gafaelfawr.yaml"
    parse_config(path)


def test_config_no_provider() -> None:
    with pytest.raises(ValidationError, match="No authentication provider"):
        parse_config(config_path("no-provider"))


def test_config_both_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAFAELFAWR_OIDC_CLIENT_SECRET", "oidc-secret")
    with pytest.raises(ValidationError, match=r"Only one of .* may be used"):
        parse_config(config_path("both-providers"))


def test_config_invalid_admin() -> None:
    with pytest.raises(ValidationError, match="invalid username"):
        parse_config(config_path("bad-admin"))


def test_config_invalid_log_level() -> None:
    with pytest.raises(ValidationError, match="logLevel"):
        parse_config(config_path("bad-log-level"))


def test_config_invalid_scope() -> None:
    with pytest.raises(ValidationError, match="invalid scope"):
        parse_config(config_path("bad-scope"))


def test_config_missing_scope() -> None:
    with pytest.raises(ValidationError, match=r"required scope .* missing"):
        parse_config(config_path("missing-scope"))


def test_config_invalid_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAFAELFAWR_BOOTSTRAP_TOKEN", "bad-token")
    with pytest.raises(ValidationError, match="Token does not start with gt-"):
        parse_config(config_path("github"))


def test_config_invalid_lifetime() -> None:
    with pytest.raises(ValidationError, match=r"must be longer than"):
        parse_config(config_path("bad-lifetime"))


def test_config_bad_groups() -> None:
    with pytest.raises(ValidationError, match="Input should be a valid list"):
        parse_config(config_path("bad-groups"))


def test_config_scope_mismatch() -> None:
    with pytest.raises(ValidationError, match=r"Scope .* assigned but not in"):
        parse_config(config_path("scope-mismatch"))


def test_config_cilogon(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAFAELFAWR_CILOGON_CLIENT_SECRET", "some-secret")
    monkeypatch.setenv("GAFAELFAWR_REDIRECT_URL", "https://example.com/login")
    config = parse_config(config_path("cilogon"))
    assert config.oidc == OIDCConfig.model_validate(
        {
            "client_id": "some-cilogon-client-id",
            "client_secret": SecretStr("some-secret"),
            "audience": "some-cilogon-client-id",
            "login_url": "https://cilogon.org/authorize",
            "login_params": {},
            "token_url": "https://cilogon.org/oauth2/token",
            "issuer": "https://cilogon.org",
            "scopes": ["email", "org.cilogon.userinfo"],
            "username_claim": "username",
        }
    )
    assert str(config.oidc.redirect_url) == "https://example.com/login"


def test_config_cilogon_test(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAFAELFAWR_CILOGON_CLIENT_SECRET", "some-secret")
    monkeypatch.setenv("GAFAELFAWR_REDIRECT_URL", "https://example.com/login")
    config = parse_config(config_path("cilogon-test"))
    assert config.oidc == OIDCConfig.model_validate(
        {
            "client_id": "some-cilogon-client-id",
            "client_secret": SecretStr("some-secret"),
            "audience": "some-cilogon-client-id",
            "enrollment_url": "https://id.example.com/some-enrollment",
            "login_url": "https://test.cilogon.org/authorize",
            "login_params": {},
            "token_url": "https://test.cilogon.org/oauth2/token",
            "issuer": "https://test.cilogon.org",
            "scopes": ["email", "org.cilogon.userinfo"],
            "username_claim": "username",
        }
    )
    assert str(config.oidc.redirect_url) == "https://example.com/login"


def test_redis_rate_limit_url(monkeypatch: pytest.MonkeyPatch) -> None:
    ephemeral = "redis://gafaelfawr-redis-ephemeral.gafaelfawr:6370/1"
    persistent = "redis://gafaelfawr-redis.gafaelfawr:6370/0"
    monkeypatch.setenv("GAFAELFAWR_REDIS_EPHEMERAL_URL", ephemeral)
    monkeypatch.setenv("GAFAELFAWR_REDIS_PERSISTENT_URL", persistent)
    monkeypatch.setenv("GAFAELFAWR_REDIS_PASSWORD", "f:b/b@c")
    config = parse_config(config_path("github"))
    assert str(config.redis_ephemeral_url) == ephemeral
    assert str(config.redis_persistent_url) == persistent
    assert config.redis_rate_limit_url == (
        "async+redis://:f%3Ab%2Fb%40c@gafaelfawr-redis-ephemeral.gafaelfawr"
        ":6370/1"
    )
