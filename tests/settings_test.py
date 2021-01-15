"""Test configuration parsing."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from gafaelfawr.config import Settings
from gafaelfawr.models.token import Token


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


def test_config_invalid_loglevel() -> None:
    settings_path = Path(__file__).parent / "settings" / "bad-loglevel.yaml"
    with pytest.raises(ValidationError):
        parse_settings(settings_path)


def test_config_invalid_token() -> None:
    settings_path = Path(__file__).parent / "settings" / "bad-token.yaml"
    with pytest.raises(ValidationError):
        parse_settings(settings_path)
