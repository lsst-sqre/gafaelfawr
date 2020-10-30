"""Test configuration parsing."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from gafaelfawr.config import Settings


def parse_settings(path: Path) -> None:
    """Parse the settings file and see if any exceptions are thrown."""
    with path.open("r") as f:
        settings = yaml.safe_load(f)
    Settings.parse_obj(settings)


def test_config_examples() -> None:
    """Check that all of the example configuration files validate."""
    examples_path = Path(__file__).parent.parent / "examples"
    for settings_path in examples_path.iterdir():
        if settings_path.name.endswith(".yaml"):
            parse_settings(settings_path)


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
