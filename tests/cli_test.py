"""Tests for the command-line interface.

Be careful when writing tests in this framework because the click command
handling code spawns its own async worker pools when needed.  You therefore
cannot use the ``setup`` fixture here because the two thread pools will
conflict with each other.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from click.testing import CliRunner
from kubernetes.client import ApiException

from gafaelfawr.cli import main
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.token import Token
from tests.support.kubernetes import MockCoreV1Api
from tests.support.settings import build_settings
from tests.support.setup import initialize

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any

    from _pytest.logging import LogCaptureFixture


def test_generate_key() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["generate-key"])

    assert result.exit_code == 0
    assert "-----BEGIN PRIVATE KEY-----" in result.output


def test_generate_token() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["generate-token"])

    assert result.exit_code == 0
    assert Token.from_str(result.output.rstrip("\n"))


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


def test_update_service_tokens(
    tmp_path: Path, mock_kubernetes: MockCoreV1Api
) -> None:
    config = initialize(tmp_path)

    runner = CliRunner()
    result = runner.invoke(main, ["update-service-tokens"])

    assert result.exit_code == 0
    assert config.kubernetes
    service_secret = config.kubernetes.service_secrets[0]
    assert mock_kubernetes.read_namespaced_secret(
        service_secret.secret_name, service_secret.secret_namespace
    )


def test_update_service_tokens_error(
    tmp_path: Path, mock_kubernetes: MockCoreV1Api, caplog: LogCaptureFixture
) -> None:
    initialize(tmp_path)

    def error_callback(method: str, *args: Any) -> None:
        if method == "list_secret_for_all_namespaces":
            raise ApiException(status=500, reason="Some error")

    MockCoreV1Api.error_callback = error_callback
    caplog.clear()
    runner = CliRunner()
    result = runner.invoke(main, ["update-service-tokens"])

    assert result.exit_code == 1
    assert [json.loads(r[2]) for r in caplog.record_tuples] == [
        {
            "event": "Unable to list service token secrets",
            "error": "Kubernetes API error: (500)\nReason: Some error\n",
            "level": "error",
            "logger": "gafaelfawr",
        },
        {
            "error": "Kubernetes API error: (500)\nReason: Some error\n",
            "event": "Failed to update service token secrets",
            "level": "error",
            "logger": "gafaelfawr",
        },
    ]


def test_update_service_tokens_no_config(
    tmp_path: Path, mock_kubernetes: MockCoreV1Api, caplog: LogCaptureFixture
) -> None:
    initialize(tmp_path)
    settings_path = build_settings(tmp_path, "oidc")
    config_dependency.set_settings_path(str(settings_path))

    caplog.clear()
    runner = CliRunner()
    result = runner.invoke(main, ["update-service-tokens"])

    assert result.exit_code == 0
    assert json.loads(caplog.record_tuples[0][2]) == {
        "event": "No Kubernetes secrets configured",
        "level": "info",
        "logger": "gafaelfawr",
    }
