"""Tests for the command-line interface."""

from __future__ import annotations

import json
import re
from unittest.mock import ANY

from click.testing import CliRunner

from gafaelfawr.cli import main
from gafaelfawr.constants import ALGORITHM


def test_generate_key() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["generate-key"])

    assert result.exit_code == 0
    assert "-----BEGIN PRIVATE KEY-----" in result.output
    assert "-----BEGIN PUBLIC KEY-----" in result.output

    match = re.search("({.*})", result.output, flags=re.DOTALL)
    assert match
    jwks = json.loads(match.group(1))
    assert jwks == {
        "alg": ALGORITHM,
        "kty": "RSA",
        "use": "sig",
        "n": ANY,
        "e": ANY,
    }


def test_help() -> None:
    runner = CliRunner()

    result = runner.invoke(main, ["-h"])
    assert result.exit_code == 0
    assert "Commands:" in result.output

    result = runner.invoke(main, ["help"])
    assert result.exit_code == 0
    assert "Commands:" in result.output

    result = runner.invoke(main, ["help", "run"])
    assert result.exit_code == 0
    assert "Options:" in result.output
    assert "Commands:" not in result.output

    result = runner.invoke(main, ["help", "unknown-command"])
    assert result.exit_code != 0
    assert "Unknown help topic unknown-command" in result.output
