"""Tests for the command-line interface."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from click.testing import CliRunner
from kubernetes.client import ApiException

from gafaelfawr.cli import main
from gafaelfawr.models.token import Token
from tests.support.kubernetes import MockCoreV1Api

if TYPE_CHECKING:
    from typing import Any

    from _pytest.logging import LogCaptureFixture

    from tests.support.setup import SetupTest


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
    setup: SetupTest, mock_kubernetes: MockCoreV1Api
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["update-service-tokens"])

    assert result.exit_code == 0
    assert setup.config.kubernetes
    service_secret = setup.config.kubernetes.service_secrets[0]
    assert mock_kubernetes.read_namespaced_secret(
        service_secret.secret_name, service_secret.secret_namespace
    )


def test_update_service_tokens_error(
    setup: SetupTest, mock_kubernetes: MockCoreV1Api, caplog: LogCaptureFixture
) -> None:
    def error_callback(method: str, *args: Any) -> None:
        if method == "list_secret_for_all_namespaces":
            raise ApiException(status=500, reason="Some error")

    MockCoreV1Api.error_callback = error_callback
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
    setup: SetupTest, mock_kubernetes: MockCoreV1Api, caplog: LogCaptureFixture
) -> None:
    setup.configure("oidc")
    assert setup.config.kubernetes is None

    runner = CliRunner()
    result = runner.invoke(main, ["update-service-tokens"])

    assert result.exit_code == 0
    assert json.loads(caplog.record_tuples[0][2]) == {
        "event": "No Kubernetes secrets configured",
        "level": "info",
        "logger": "gafaelfawr",
    }
