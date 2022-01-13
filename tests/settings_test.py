"""Test configuration parsing."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from gafaelfawr.config import Settings
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.token import Token

from .support.settings import build_settings


def parse_settings(path: Path, fix_token: bool = False) -> None:
    """Parse the settings file and see if any exceptions are thrown.

    Parameters
    ----------
    path : `pathlib.Path`
        The path to the settings file to test.
    fix_token : `bool`, optional
        Whether to fix an invalid ``bootstrap_token`` before checking the
        settings file.  Some examples have intentionally invalid tokens.
    """
    with path.open("r") as f:
        settings = yaml.safe_load(f)

    # Avoid errors from an invalid bootstrap token in one of the examples.
    if fix_token and "bootstrap_token" in settings:
        settings["bootstrap_token"] = str(Token())

    Settings.parse_obj(settings)


def test_config_examples() -> None:
    """Check that all of the example configuration files validate."""
    examples_path = Path(__file__).parent.parent / "examples"
    for settings_path in examples_path.iterdir():
        if settings_path.name.endswith(".yaml"):
            parse_settings(settings_path, fix_token=True)


def test_config_no_provider() -> None:
    settings_path = Path(__file__).parent / "settings" / "no-provider.yaml"
    with pytest.raises(ValidationError):
        parse_settings(settings_path)


def test_config_both_providers() -> None:
    settings_path = Path(__file__).parent / "settings" / "both-providers.yaml"
    with pytest.raises(ValidationError):
        parse_settings(settings_path)


def test_config_invalid_admin() -> None:
    settings_path = Path(__file__).parent / "settings" / "bad-admin.yaml"
    with pytest.raises(ValidationError):
        parse_settings(settings_path)


def test_config_invalid_loglevel() -> None:
    settings_path = Path(__file__).parent / "settings" / "bad-loglevel.yaml"
    with pytest.raises(ValidationError):
        parse_settings(settings_path)


def test_config_invalid_scope() -> None:
    settings_path = Path(__file__).parent / "settings" / "bad-scope.yaml"
    with pytest.raises(ValidationError):
        parse_settings(settings_path)


def test_config_invalid_token() -> None:
    settings_path = Path(__file__).parent / "settings" / "bad-token.yaml"
    with pytest.raises(ValidationError):
        parse_settings(settings_path)


def test_config_missing_scope() -> None:
    settings_path = Path(__file__).parent / "settings" / "missing-scope.yaml"
    with pytest.raises(ValidationError):
        parse_settings(settings_path)


@pytest.mark.asyncio
async def test_database_password(tmp_path: Path) -> None:
    settings_path = build_settings(
        tmp_path,
        "github",
        database_url="postgresql://gafaelfawr@localhost/gafaelfawr",
    )

    os.environ["GAFAELFAWR_DATABASE_PASSWORD"] = "some-password"
    config_dependency.set_settings_path(str(settings_path))
    config = await config_dependency()
    del os.environ["GAFAELFAWR_DATABASE_PASSWORD"]

    expected = (
        "postgresql+asyncpg://gafaelfawr:some-password@localhost/gafaelfawr"
    )
    assert config.database_url == expected
