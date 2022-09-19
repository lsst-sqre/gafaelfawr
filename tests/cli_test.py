"""Tests for the command-line interface.

Be careful when writing tests in this framework because the click command
handling code spawns its own async worker pools when needed.  None of these
tests can therefore be async, and should instead run coroutines using the
``event_loop`` fixture when needed.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import structlog
from _pytest.logging import LogCaptureFixture
from click.testing import CliRunner
from cryptography.fernet import Fernet
from kubernetes_asyncio.client import ApiException
from safir.database import initialize_database
from safir.testing.kubernetes import MockKubernetesApi
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.cli import main
from gafaelfawr.config import Config, OIDCClient
from gafaelfawr.constants import CHANGE_HISTORY_RETENTION
from gafaelfawr.exceptions import InvalidGrantError
from gafaelfawr.factory import Factory
from gafaelfawr.models.admin import Admin
from gafaelfawr.models.history import TokenChange, TokenChangeHistoryEntry
from gafaelfawr.models.oidc import OIDCAuthorizationCode
from gafaelfawr.models.token import Token, TokenData, TokenType, TokenUserInfo
from gafaelfawr.schema import Base
from gafaelfawr.storage.history import TokenChangeHistoryStore
from gafaelfawr.storage.token import TokenDatabaseStore
from gafaelfawr.util import current_datetime

from .support.logging import parse_log
from .support.settings import configure
from .support.slack import MockSlack


async def _initialize_database(engine: AsyncEngine, config: Config) -> None:
    """Helper function to initialize the database."""
    logger = structlog.get_logger("gafaelfawr")
    await initialize_database(engine, logger, schema=Base.metadata, reset=True)


def test_audit(
    tmp_path: Path,
    config: Config,
    engine: AsyncEngine,
    event_loop: asyncio.AbstractEventLoop,
    mock_slack: MockSlack,
) -> None:
    logger = structlog.get_logger("gafaelfawr")
    now = current_datetime()
    token_data = TokenData(
        token=Token(),
        username="some-user",
        token_type=TokenType.session,
        scopes=["user:token"],
        created=now,
        expires=now + timedelta(days=7),
    )

    async def setup() -> None:
        await initialize_database(engine, logger, schema=Base.metadata)
        async with Factory.standalone(config, engine) as factory:
            token_db_store = TokenDatabaseStore(factory.session)
            async with factory.session.begin():
                await token_db_store.add(token_data)

    event_loop.run_until_complete(setup())
    runner = CliRunner()
    result = runner.invoke(main, ["audit"])
    assert result.exit_code == 0

    alerts = [
        f"Token `{token_data.token.key}` for `some-user` found in database"
        " but not Redis",
    ]
    expected_alert = (
        "Gafaelfawr data inconsistencies found:\n* "
        + "\n* ".join(alerts)
        + "\n"
    )
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": expected_alert},
                }
            ]
        }
    ]


def test_delete_all_data(
    tmp_path: Path,
    engine: AsyncEngine,
    event_loop: asyncio.AbstractEventLoop,
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    config = configure(tmp_path, "github-oidc-server", oidc_clients=clients)
    logger = structlog.get_logger("gafaelfawr")

    async def setup() -> OIDCAuthorizationCode:
        await initialize_database(engine, logger, schema=Base.metadata)
        async with Factory.standalone(config, engine) as factory:
            token_service = factory.create_token_service()
            user_info = TokenUserInfo(username="some-user")
            token = await token_service.create_session_token(
                user_info, scopes=[], ip_address="127.0.0.1"
            )
            oidc_service = factory.create_oidc_service()
            return await oidc_service.issue_code(
                "some-id", "https://example.com/", token
            )

    code = event_loop.run_until_complete(setup())
    runner = CliRunner()
    result = runner.invoke(main, ["delete-all-data"])
    assert result.exit_code == 0

    async def check_data() -> None:
        async with Factory.standalone(config, engine) as factory:
            admin_service = factory.create_admin_service()
            expected = [Admin(username=u) for u in config.initial_admins]
            assert await admin_service.get_admins() == expected
            token_service = factory.create_token_service()
            bootstrap = TokenData.bootstrap_token()
            assert await token_service.list_tokens(bootstrap) == []
            oidc_service = factory.create_oidc_service()
            with pytest.raises(InvalidGrantError):
                await oidc_service.redeem_code(
                    "some-id", "some-secret", "https://example.com/", code
                )

    event_loop.run_until_complete(check_data())


def test_generate_key() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["generate-key"])

    assert result.exit_code == 0
    assert "-----BEGIN PRIVATE KEY-----" in result.output


def test_generate_session_secret() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["generate-session-secret"])

    assert result.exit_code == 0
    assert Fernet(result.output.rstrip("\n").encode())


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
        async with Factory.standalone(config, engine) as factory:
            admin_service = factory.create_admin_service()
            expected = [Admin(username=u) for u in config.initial_admins]
            assert await admin_service.get_admins() == expected
            token_service = factory.create_token_service()
            bootstrap = TokenData.bootstrap_token()
            assert await token_service.list_tokens(bootstrap) == []

    event_loop.run_until_complete(check_database())


def test_maintenance(
    engine: AsyncEngine, config: Config, event_loop: asyncio.AbstractEventLoop
) -> None:
    now = datetime.now(tz=timezone.utc)
    token_data = TokenData(
        token=Token(),
        username="some-user",
        token_type=TokenType.session,
        scopes=["read:all", "user:token"],
        created=now - timedelta(minutes=60),
        expires=now - timedelta(minutes=30),
    )
    new_token_data = TokenData(
        token=Token(),
        username="some-user",
        token_type=TokenType.session,
        scopes=["read:all", "user:token"],
        created=now - timedelta(minutes=60),
        expires=now + timedelta(minutes=30),
    )
    old_history_entry = TokenChangeHistoryEntry(
        token=Token().key,
        username="other-user",
        token_type=TokenType.session,
        scopes=[],
        expires=now - CHANGE_HISTORY_RETENTION + timedelta(days=10),
        actor="other-user",
        action=TokenChange.create,
        ip_address="127.0.0.1",
        event_time=now - CHANGE_HISTORY_RETENTION - timedelta(minutes=1),
    )

    async def initialize() -> None:
        async with Factory.standalone(config, engine) as factory:
            async with factory.session.begin():
                token_store = TokenDatabaseStore(factory.session)
                await token_store.add(token_data)
                await token_store.add(new_token_data)
                history_store = TokenChangeHistoryStore(factory.session)
                await history_store.add(old_history_entry)

    event_loop.run_until_complete(initialize())
    runner = CliRunner()
    result = runner.invoke(main, ["maintenance"])
    assert result.exit_code == 0

    async def check_database() -> None:
        async with Factory.standalone(config, engine) as factory:
            async with factory.session.begin():
                token_store = TokenDatabaseStore(factory.session)
                assert await token_store.get_info(token_data.token.key) is None
                assert await token_store.get_info(new_token_data.token.key)
                history_store = TokenChangeHistoryStore(factory.session)
                history = await history_store.list(username="other-user")
                assert history.entries == []

    event_loop.run_until_complete(check_database())


def test_openapi_schema(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["openapi-schema"])
    assert result.exit_code == 0
    assert json.loads(result.output)
    assert "Return to Gafaelfawr documentation" not in result.output
    schema = result.output

    result = runner.invoke(
        main, ["openapi-schema", "--output", str(tmp_path / "openapi.json")]
    )
    assert result.exit_code == 0
    assert result.output == ""
    assert (tmp_path / "openapi.json").read_text() == schema

    result = runner.invoke(main, ["openapi-schema", "--add-back-link"])
    assert result.exit_code == 0
    assert "Return to Gafaelfawr documentation" in result.output


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
                    "service": "bot-mobu",
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
