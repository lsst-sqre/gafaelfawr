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
    monkeypatch.setenv("GAFAELFAWR_BOOTSTRAP_TOKEN", str(Token()))
    monkeypatch.setenv("GAFAELFAWR_GITHUB_CLIENT_SECRET", "github-secret")
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
    with pytest.raises(ValidationError):
        parse_config(config_path("no-provider"))


def test_config_both_providers() -> None:
    with pytest.raises(ValidationError):
        parse_config(config_path("both-providers"))


def test_config_invalid_admin() -> None:
    with pytest.raises(ValidationError):
        parse_config(config_path("bad-admin"))


def test_config_invalid_log_level() -> None:
    with pytest.raises(ValidationError):
        parse_config(config_path("bad-log-level"))


def test_config_invalid_scope() -> None:
    with pytest.raises(ValidationError):
        parse_config(config_path("bad-scope"))


def test_config_missing_scope() -> None:
    with pytest.raises(ValidationError):
        parse_config(config_path("missing-scope"))


def test_config_invalid_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAFAELFAWR_BOOTSTRAP_TOKEN", "bad-token")
    with pytest.raises(ValidationError):
        parse_config(config_path("github"))


def test_config_bad_groups() -> None:
    with pytest.raises(ValidationError):
        parse_config(config_path("bad-groups"))


def test_config_cilogon(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAFAELFAWR_CILOGON_CLIENT_SECRET", "some-secret")
    monkeypatch.setenv("GAFAELFAWR_REDIRECT_URL", "https://example.com/login")
    config = parse_config(config_path("cilogon"))
    assert config.oidc == OIDCConfig(
        client_id="some-cilogon-client-id",
        client_secret=SecretStr("some-secret"),
        audience="some-cilogon-client-id",
        login_url="https://cilogon.org/authorize",
        login_params={},
        token_url="https://cilogon.org/oauth2/token",
        issuer="https://cilogon.org",
        scopes=["email", "org.cilogon.userinfo"],
        username_claim="username",
    )
    assert config.oidc.redirect_url == "https://example.com/login"


def test_config_cilogon_test(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAFAELFAWR_CILOGON_CLIENT_SECRET", "some-secret")
    monkeypatch.setenv("GAFAELFAWR_REDIRECT_URL", "https://example.com/login")
    config = parse_config(config_path("cilogon-test"))
    assert config.oidc == OIDCConfig(
        client_id="some-cilogon-client-id",
        client_secret=SecretStr("some-secret"),
        audience="some-cilogon-client-id",
        login_url="https://test.cilogon.org/authorize",
        login_params={},
        token_url="https://test.cilogon.org/oauth2/token",
        issuer="https://test.cilogon.org",
        scopes=["email", "org.cilogon.userinfo"],
        username_claim="username",
    )
    assert config.oidc.redirect_url == "https://example.com/login"
