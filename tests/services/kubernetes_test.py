"""Tests for Kubernetes secret management."""

from __future__ import annotations

import json
from base64 import b64decode, b64encode
from datetime import timedelta
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest
from kubernetes.client import ApiException, V1ObjectMeta, V1Secret

from gafaelfawr.constants import KUBERNETES_TOKEN_TYPE_LABEL
from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenType,
)
from gafaelfawr.util import current_datetime
from tests.support.kubernetes import (
    MockCoreV1Api,
    assert_kubernetes_objects_are,
)

if TYPE_CHECKING:
    from typing import Any

    from _pytest.logging import LogCaptureFixture

    from gafaelfawr.services.token import TokenService
    from tests.support.setup import SetupTest


def token_as_base64(token: Token) -> str:
    return b64encode(str(token).encode()).decode()


async def token_data_from_secret(
    token_service: TokenService, secret: V1Secret
) -> TokenData:
    assert "token" in secret.data
    token = b64decode(secret.data["token"].encode()).decode()
    data = await token_service.get_data(Token.from_str(token))
    assert data
    return data


async def assert_kubernetes_secrets_match_config(
    setup: SetupTest, mock_kubernetes: MockCoreV1Api, is_fresh: bool = True
) -> None:
    assert setup.config.kubernetes
    token_service = setup.factory.create_token_service()

    expected = [
        V1Secret(
            api_version="v1",
            data={"token": ANY},
            metadata=V1ObjectMeta(
                labels={KUBERNETES_TOKEN_TYPE_LABEL: "service"},
                name=s.secret_name,
                namespace=s.secret_namespace,
            ),
            type="Opaque",
        )
        for s in setup.config.kubernetes.service_secrets
    ]
    assert_kubernetes_objects_are(mock_kubernetes, expected)

    for service_secret in setup.config.kubernetes.service_secrets:
        secret = mock_kubernetes.read_namespaced_secret(
            service_secret.secret_name, service_secret.secret_namespace
        )
        data = await token_data_from_secret(token_service, secret)
        assert data == TokenData(
            token=data.token,
            username=service_secret.service,
            token_type=TokenType.service,
            scopes=service_secret.scopes,
            created=data.created,
            expires=None,
            name=None,
            uid=None,
            groups=None,
        )
        if is_fresh:
            now = current_datetime()
            assert now - timedelta(seconds=5) <= data.created <= now


@pytest.mark.asyncio
async def test_create(
    setup: SetupTest, mock_kubernetes: MockCoreV1Api, caplog: LogCaptureFixture
) -> None:
    assert setup.config.kubernetes
    kubernetes_service = setup.factory.create_kubernetes_service()
    await kubernetes_service.update_service_secrets()
    await assert_kubernetes_secrets_match_config(setup, mock_kubernetes)

    expected_tuples = [
        (
            {
                "event": "Created new service token",
                "key": ANY,
                "level": "info",
                "logger": "gafaelfawr",
                "token_scope": ",".join(s.scopes),
                "token_username": s.service,
            },
            {
                "event": (
                    f"Created {s.secret_namespace}/{s.secret_name} secret"
                ),
                "level": "info",
                "logger": "gafaelfawr",
                "scopes": s.scopes,
                "service": s.service,
            },
        )
        for s in setup.config.kubernetes.service_secrets
    ]
    expected = [r for t in expected_tuples for r in t]
    assert [json.loads(r[2]) for r in caplog.record_tuples] == expected

    # Running creation again should not change anything.
    caplog.clear()
    objects = mock_kubernetes.get_all_objects_for_test()
    await kubernetes_service.update_service_secrets()
    assert mock_kubernetes.get_all_objects_for_test() == objects
    assert caplog.record_tuples == []


@pytest.mark.asyncio
async def test_modify(
    setup: SetupTest, mock_kubernetes: MockCoreV1Api, caplog: LogCaptureFixture
) -> None:
    assert setup.config.kubernetes
    assert len(setup.config.kubernetes.service_secrets) >= 2
    service_secret_one = setup.config.kubernetes.service_secrets[0]
    service_secret_two = setup.config.kubernetes.service_secrets[1]
    kubernetes_service = setup.factory.create_kubernetes_service()
    token_service = setup.factory.create_token_service()

    # Secret that shouldn't exist.
    secret = V1Secret(
        api_version="v1",
        data={"token": "bogus"},
        metadata=V1ObjectMeta(
            labels={KUBERNETES_TOKEN_TYPE_LABEL: "service"},
            name="foo",
            namespace="bar",
        ),
        type="Opaque",
    )
    mock_kubernetes.create_namespaced_secret("bar", secret)

    # Valid secret but with a bogus token.
    secret = V1Secret(
        api_version="v1",
        data={"token": "bogus"},
        metadata=V1ObjectMeta(
            labels={KUBERNETES_TOKEN_TYPE_LABEL: "service"},
            name=service_secret_one.secret_name,
            namespace=service_secret_one.secret_namespace,
        ),
        type="Opaque",
    )
    mock_kubernetes.create_namespaced_secret(
        service_secret_one.secret_namespace, secret
    )

    # Valid secret but with a nonexistent token.
    secret = V1Secret(
        api_version="v1",
        data={"token": token_as_base64(Token())},
        metadata=V1ObjectMeta(
            labels={KUBERNETES_TOKEN_TYPE_LABEL: "service"},
            name=service_secret_two.secret_name,
            namespace=service_secret_two.secret_namespace,
        ),
        type="Opaque",
    )
    mock_kubernetes.create_namespaced_secret(
        service_secret_two.secret_namespace, secret
    )

    # Update the secrets.  This should delete the secret that shouldn't exist
    # and update the two that should with fresh secrets.
    await kubernetes_service.update_service_secrets()
    await assert_kubernetes_secrets_match_config(setup, mock_kubernetes)

    # Check the logging.
    expected = [
        {
            "event": "Deleted bar/foo secret",
            "level": "info",
            "logger": "gafaelfawr",
        },
        {
            "event": "Created new service token",
            "key": ANY,
            "level": "info",
            "logger": "gafaelfawr",
            "token_scope": ",".join(service_secret_one.scopes),
            "token_username": service_secret_one.service,
        },
        {
            "event": (
                f"Updated {service_secret_one.secret_namespace}"
                f"/{service_secret_one.secret_name} secret"
            ),
            "level": "info",
            "logger": "gafaelfawr",
            "scopes": service_secret_one.scopes,
            "service": service_secret_one.service,
        },
        {
            "event": "Created new service token",
            "key": ANY,
            "level": "info",
            "logger": "gafaelfawr",
            "token_scope": ",".join(service_secret_two.scopes),
            "token_username": service_secret_two.service,
        },
        {
            "event": (
                f"Updated {service_secret_two.secret_namespace}"
                f"/{service_secret_two.secret_name} secret"
            ),
            "level": "info",
            "logger": "gafaelfawr",
            "scopes": service_secret_two.scopes,
            "service": service_secret_two.service,
        },
    ]
    assert [json.loads(r[2]) for r in caplog.record_tuples] == expected

    # Replace one secret with a valid token for the wrong service.
    token = await token_service.create_token_from_admin_request(
        AdminTokenRequest(
            username="some-other-service",
            token_type=TokenType.service,
            scopes=service_secret_one.scopes,
        ),
        TokenData.internal_token(),
        ip_address=None,
    )
    secret = V1Secret(
        api_version="v1",
        data={"token": token_as_base64(token)},
        metadata=V1ObjectMeta(
            labels={KUBERNETES_TOKEN_TYPE_LABEL: "service"},
            name=service_secret_one.secret_name,
            namespace=service_secret_one.secret_namespace,
        ),
        type="Opaque",
    )
    mock_kubernetes.delete_namespaced_secret(
        service_secret_one.secret_name, service_secret_one.secret_namespace
    )
    mock_kubernetes.create_namespaced_secret(
        service_secret_one.secret_namespace, secret
    )

    # Replace the other token with a valid token with the wrong scopes.
    token = await token_service.create_token_from_admin_request(
        AdminTokenRequest(
            username=service_secret_two.service,
            token_type=TokenType.service,
            scopes=["read:all"],
        ),
        TokenData.internal_token(),
        ip_address=None,
    )
    secret = V1Secret(
        api_version="v1",
        data={"token": token_as_base64(token)},
        metadata=V1ObjectMeta(
            labels={KUBERNETES_TOKEN_TYPE_LABEL: "service"},
            name=service_secret_two.secret_name,
            namespace=service_secret_two.secret_namespace,
        ),
        type="Opaque",
    )
    mock_kubernetes.delete_namespaced_secret(
        service_secret_two.secret_name, service_secret_two.secret_namespace
    )
    mock_kubernetes.create_namespaced_secret(
        service_secret_two.secret_namespace, secret
    )

    # Update the secrets.  This should create new tokens for both.
    await kubernetes_service.update_service_secrets()
    await assert_kubernetes_secrets_match_config(setup, mock_kubernetes)

    # Finally, replace a secret with one with no token.
    secret = V1Secret(
        api_version="v1",
        data={},
        metadata=V1ObjectMeta(
            labels={KUBERNETES_TOKEN_TYPE_LABEL: "service"},
            name=service_secret_one.secret_name,
            namespace=service_secret_one.secret_namespace,
        ),
        type="Opaque",
    )
    mock_kubernetes.delete_namespaced_secret(
        service_secret_one.secret_name, service_secret_one.secret_namespace
    )
    mock_kubernetes.create_namespaced_secret(
        service_secret_one.secret_namespace, secret
    )

    # Update the secrets.  This should create a new token for the first secret
    # but not for the second.
    await kubernetes_service.update_service_secrets()
    await assert_kubernetes_secrets_match_config(
        setup, mock_kubernetes, is_fresh=False
    )


@pytest.mark.asyncio
async def test_ignore(
    setup: SetupTest, mock_kubernetes: MockCoreV1Api
) -> None:
    assert setup.config.kubernetes
    kubernetes_service = setup.factory.create_kubernetes_service()

    # Create a secret without the expected label.
    secret_one = V1Secret(
        api_version="v1",
        data={"foo": "bar"},
        metadata=V1ObjectMeta(name="secret-one", namespace="mobu"),
        type="Opaque",
    )
    mock_kubernetes.create_namespaced_secret("mobu", secret_one)

    # Create a secret with the expected label but a different value.
    secret_two = V1Secret(
        api_version="v1",
        data={"token": token_as_base64(Token())},
        metadata=V1ObjectMeta(
            labels={KUBERNETES_TOKEN_TYPE_LABEL: "other"},
            name="secret-two",
            namespace="elsewhere",
        ),
        type="Opaque",
    )
    mock_kubernetes.create_namespaced_secret("elsewhere", secret_two)

    # Update the secrets.  Both of our secrets should survive unmolested.
    await kubernetes_service.update_service_secrets()
    objects = mock_kubernetes.get_all_objects_for_test()
    assert secret_one in objects
    assert secret_two in objects

    # Delete our secrets and then check that the created secrets are right.
    mock_kubernetes.delete_namespaced_secret("secret-one", "mobu")
    mock_kubernetes.delete_namespaced_secret("secret-two", "elsewhere")
    await assert_kubernetes_secrets_match_config(setup, mock_kubernetes)


@pytest.mark.asyncio
async def test_errors_delete_patch(
    setup: SetupTest, mock_kubernetes: MockCoreV1Api
) -> None:
    assert setup.config.kubernetes
    assert len(setup.config.kubernetes.service_secrets) >= 2
    service_secret = setup.config.kubernetes.service_secrets[0]
    kubernetes_service = setup.factory.create_kubernetes_service()
    token_service = setup.factory.create_token_service()

    # Create a secret that should not exist.
    secret_one = V1Secret(
        api_version="v1",
        data={"token", "bar"},
        metadata=V1ObjectMeta(
            labels={KUBERNETES_TOKEN_TYPE_LABEL: "service"},
            name="secret",
            namespace="elsewhere",
        ),
        type="Opaque",
    )
    mock_kubernetes.create_namespaced_secret("elsewhere", secret_one)

    # Create a secret that should exist but has an invalid token.
    secret_two = V1Secret(
        api_version="v1",
        data={"token": token_as_base64(Token())},
        metadata=V1ObjectMeta(
            labels={KUBERNETES_TOKEN_TYPE_LABEL: "service"},
            name=service_secret.secret_name,
            namespace=service_secret.secret_namespace,
        ),
        type="Opaque",
    )
    mock_kubernetes.create_namespaced_secret(
        service_secret.secret_namespace, secret_two
    )

    # Simulate some errors.  The callback function takes the operation and the
    # secret name.
    def error_callback(method: str, *args: Any) -> None:
        if method in ("delete_namespaced_secret", "patch_namespaced_secret"):
            raise ApiException(status=500, reason="Some error")

    MockCoreV1Api.error_callback = error_callback

    # Now run the synchronization.  secret_one and secret_two should be left
    # unchanged, but we should still create the second missing service secret.
    await kubernetes_service.update_service_secrets()
    objects = mock_kubernetes.get_all_objects_for_test()
    assert secret_one in objects
    assert secret_two in objects
    service_secret = setup.config.kubernetes.service_secrets[1]
    secret = mock_kubernetes.read_namespaced_secret(
        service_secret.secret_name, service_secret.secret_namespace
    )
    assert secret.metadata.name == service_secret.secret_name
    assert secret.metadata.namespace == service_secret.secret_namespace
    assert await token_data_from_secret(token_service, secret)

    # Try again, but simulating an error in retrieving a secret.
    def error_callback_read(method: str, *args: Any) -> None:
        if method == "read_namespaced_secret":
            if args[1] != "elsewhere":
                raise ApiException(status=500, reason="Some error")

    MockCoreV1Api.error_callback = error_callback_read

    # Now run the synchronization.  secret_one should be deleted and
    # secret_two should be left unchanged.
    await kubernetes_service.update_service_secrets()
    objects = mock_kubernetes.get_all_objects_for_test()
    assert secret_one not in objects
    assert secret_two in objects


@pytest.mark.asyncio
async def test_create_not_ours(
    setup: SetupTest, mock_kubernetes: MockCoreV1Api, caplog: LogCaptureFixture
) -> None:
    assert setup.config.kubernetes
    assert len(setup.config.kubernetes.service_secrets) >= 1
    service_secret = setup.config.kubernetes.service_secrets[-1]
    kubernetes_service = setup.factory.create_kubernetes_service()

    # Create a secret that should exist but doesn't have our annotation.
    secret = V1Secret(
        api_version="v1",
        data={"token": token_as_base64(Token())},
        metadata=V1ObjectMeta(
            name=service_secret.secret_name,
            namespace=service_secret.secret_namespace,
        ),
        type="Opaque",
    )
    mock_kubernetes.create_namespaced_secret(
        service_secret.secret_namespace, secret
    )

    # Now run the synchronization.  secret_one and secret_two should be left
    # unchanged, and we should log errors about failing to do the update.
    await kubernetes_service.update_service_secrets()
    objects = mock_kubernetes.get_all_objects_for_test()
    assert secret in objects
    assert json.loads(caplog.record_tuples[-1][2]) == {
        "event": (
            f"Creating {service_secret.secret_namespace}"
            f"/{service_secret.secret_name} failed"
        ),
        "error": (
            f"Kubernetes API error: (500)\n"
            f"Reason: {service_secret.secret_namespace}"
            f"/{service_secret.secret_name} exists\n"
        ),
        "level": "error",
        "logger": "gafaelfawr",
    }
