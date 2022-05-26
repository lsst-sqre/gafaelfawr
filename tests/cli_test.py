"""Tests for the command-line interface.

Be careful when writing tests in this framework because the click command
handling code spawns its own async worker pools when needed.  None of these
tests can therefore be async, and should instead run coroutines using the
``event_loop`` fixture when needed.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import call, patch

import structlog
from _pytest.logging import LogCaptureFixture
from click.testing import CliRunner
from kubernetes_asyncio.client import ApiException
from safir.database import initialize_database
from safir.testing.kubernetes import MockKubernetesApi
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.cli import main
from gafaelfawr.config import Config
from gafaelfawr.constants import UID_USER_MIN
from gafaelfawr.factory import Factory
from gafaelfawr.models.admin import Admin
from gafaelfawr.models.token import Token, TokenData
from gafaelfawr.schema import Base

from .support.firestore import MockFirestore
from .support.logging import parse_log
from .support.settings import configure


async def _initialize_database(engine: AsyncEngine, config: Config) -> None:
    """Helper function to initialize the database."""
    logger = structlog.get_logger("gafaelfawr")
    await initialize_database(engine, logger, schema=Base.metadata, reset=True)


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


def test_init(
    engine: AsyncEngine, config: Config, event_loop: asyncio.AbstractEventLoop
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["init"])
    assert result.exit_code == 0

    async def check_database() -> None:
        # Dispose of the engine's connection pool at this point because its
        # cache will be invalid due to the recreation of the database schema.
        # (asyncpg will invalidate its cache automatically if it sees the
        # schema changes, but the init CLI function will have created a new,
        # independent engine.)
        await engine.dispose()

        async with Factory.standalone(config, engine) as factory:
            admin_service = factory.create_admin_service()
            expected = [Admin(username=u) for u in config.initial_admins]
            assert await admin_service.get_admins() == expected
            token_service = factory.create_token_service()
            bootstrap = TokenData.bootstrap_token()
            assert await token_service.list_tokens(bootstrap) == []

    event_loop.run_until_complete(check_database())


def test_fix_home_ownership(
    tmp_path: Path,
    engine: AsyncEngine,
    event_loop: asyncio.AbstractEventLoop,
    mock_firestore: MockFirestore,
) -> None:
    configure(tmp_path, "oidc-firestore")
    home = tmp_path / "home"
    home.mkdir()
    user_home = home / "someuser"
    user_home.mkdir()

    runner = CliRunner()
    result = runner.invoke(main, ["init"])
    assert result.exit_code == 0
    with patch.object(subprocess, "run") as mock_run:
        result = runner.invoke(main, ["fix-home-ownership", str(home)])
        print(result)
        print(result.output)
        assert result.exit_code == 0

        assert mock_run.call_count == 1
        document = mock_firestore.collection("users").document("someuser")
        user = document.get_for_testing()
        assert user.exists
        uid = user["uid"]
        assert uid == UID_USER_MIN
        assert mock_run.call_args == call(
            ["chown", "-R", f"{uid}:{uid}", str(user_home)]
        )


def test_update_service_tokens(
    tmp_path: Path,
    engine: AsyncEngine,
    config: Config,
    event_loop: asyncio.AbstractEventLoop,
    mock_kubernetes: MockKubernetesApi,
) -> None:
    event_loop.run_until_complete(_initialize_database(engine, config))
    event_loop.run_until_complete(
        mock_kubernetes.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            "mobu",
            "gafaelfawrservicetokens",
            {
                "apiVersion": "gafaelfawr.lsst.io/v1alpha1",
                "kind": "GafaelfawrServiceToken",
                "metadata": {
                    "name": "gafaelfawr-secret",
                    "namespace": "mobu",
                    "generation": 1,
                },
                "spec": {
                    "service": "mobu",
                    "scopes": ["admin:token"],
                },
            },
        )
    )

    runner = CliRunner()
    result = runner.invoke(main, ["update-service-tokens"])

    assert result.exit_code == 0
    assert mock_kubernetes.get_all_objects_for_test("Secret")


def test_update_service_tokens_error(
    tmp_path: Path,
    engine: AsyncEngine,
    config: Config,
    event_loop: asyncio.AbstractEventLoop,
    mock_kubernetes: MockKubernetesApi,
    caplog: LogCaptureFixture,
) -> None:
    event_loop.run_until_complete(_initialize_database(engine, config))
    caplog.clear()

    def error_callback(method: str, *args: Any) -> None:
        if method == "list_cluster_custom_object":
            raise ApiException(status=500, reason="Some error")

    mock_kubernetes.error_callback = error_callback
    runner = CliRunner()
    result = runner.invoke(main, ["update-service-tokens"])

    assert result.exit_code == 1
    assert parse_log(caplog) == [
        {
            "event": "Unable to list GafaelfawrServiceToken objects",
            "error": "Kubernetes API error: (500)\nReason: Some error\n",
            "severity": "error",
        },
        {
            "error": "Kubernetes API error: (500)\nReason: Some error\n",
            "event": "Failed to update service token secrets",
            "severity": "error",
        },
    ]
