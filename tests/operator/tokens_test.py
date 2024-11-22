"""Tests for Kubernetes secret management."""

from __future__ import annotations

import asyncio
from base64 import b64decode, b64encode
from datetime import timedelta
from typing import Any
from unittest.mock import ANY

import pytest
from kubernetes_asyncio import client
from kubernetes_asyncio.client import (
    ApiClient,
    ApiException,
    V1ObjectMeta,
    V1Secret,
)
from safir.datetime import current_datetime

from gafaelfawr.constants import KUBERNETES_TIMER_DELAY
from gafaelfawr.factory import Factory
from gafaelfawr.models.kubernetes import (
    GafaelfawrServiceTokenSpec,
    KubernetesResourceStatus,
    StatusReason,
)
from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenType,
)
from gafaelfawr.services.token import TokenService

from ..support.kubernetes import (
    assert_custom_resource_status_is,
    assert_resources_match,
    create_custom_resources,
    operator_running,
    operator_test_input,
    operator_test_output,
    requires_kubernetes,
    run_operator_once,
)


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


async def assert_secret_token_matches_spec(
    factory: Factory,
    api_client: ApiClient,
    name: str,
    namespace: str,
    spec: GafaelfawrServiceTokenSpec,
    *,
    is_fresh: bool = True,
) -> None:
    token_service = factory.create_token_service()
    core_api = client.CoreV1Api(api_client)
    secret = await core_api.read_namespaced_secret(name, namespace)
    data = await token_data_from_secret(token_service, secret)
    assert data == TokenData(
        token=data.token,
        username=spec.service,
        token_type=TokenType.service,
        scopes=spec.scopes,
        created=data.created,
        expires=None,
        name=None,
        uid=None,
        groups=None,
    )
    if is_fresh:
        now = current_datetime()
        assert now - timedelta(seconds=30) <= data.created <= now


async def assert_secrets_match(
    factory: Factory,
    api_client: ApiClient,
    tokens: list[dict[str, Any]],
    *,
    is_fresh: bool = True,
) -> None:
    for token in tokens:
        name = token["metadata"]["name"]
        namespace = token["metadata"]["namespace"]
        spec = GafaelfawrServiceTokenSpec.model_validate(token["spec"])
        await assert_secret_token_matches_spec(
            factory, api_client, name, namespace, spec
        )


@requires_kubernetes
@pytest.mark.asyncio
async def test_create(
    factory: Factory, api_client: ApiClient, namespace: str
) -> None:
    tokens = operator_test_input("tokens", namespace)
    await create_custom_resources(api_client, tokens)

    await run_operator_once("gafaelfawr.operator")

    secrets = operator_test_output("tokens", namespace)
    await assert_resources_match(api_client, secrets)
    await assert_secrets_match(factory, api_client, tokens)
    for token in tokens:
        status = KubernetesResourceStatus(
            message="Secret was created",
            generation=ANY,
            reason=StatusReason.Created,
            timestamp=ANY,
        )
        await assert_custom_resource_status_is(api_client, token, status)


@requires_kubernetes
@pytest.mark.asyncio
async def test_secret_verification(
    factory: Factory, api_client: ApiClient, namespace: str
) -> None:
    tokens = operator_test_input("tokens", namespace)
    await create_custom_resources(api_client, tokens)
    token_service = factory.create_token_service()
    core_api = client.CoreV1Api(api_client)

    # Valid secret but with a bogus token.
    secret = V1Secret(
        api_version="v1",
        kind="Secret",
        data={"token": b64encode(b"bogus").decode()},
        metadata=V1ObjectMeta(
            name=tokens[0]["metadata"]["name"], namespace=namespace
        ),
        type="Opaque",
    )
    await core_api.create_namespaced_secret(namespace, secret)

    # Valid secret but with a nonexistent token.
    secret = V1Secret(
        api_version="v1",
        kind="Secret",
        data={"token": token_as_base64(Token())},
        metadata=V1ObjectMeta(
            name=tokens[1]["metadata"]["name"],
            namespace=namespace,
            labels=tokens[1]["metadata"]["labels"],
            annotations=tokens[1]["metadata"]["annotations"],
        ),
        type="Opaque",
    )
    await core_api.create_namespaced_secret(namespace, secret)

    # Run the operator.  This should replace both with fresh secrets.
    await run_operator_once("gafaelfawr.operator")
    secrets = operator_test_output("tokens", namespace)
    await assert_resources_match(api_client, secrets)
    await assert_secrets_match(factory, api_client, tokens)

    # Replace one secret with a valid token for the wrong service.
    token = await token_service.create_token_from_admin_request(
        AdminTokenRequest(
            username="bot-some-other-service",
            token_type=TokenType.service,
            scopes=["admin:token"],
        ),
        TokenData.internal_token(),
        ip_address=None,
    )
    secret = V1Secret(
        api_version="v1",
        kind="Secret",
        data={"token": token_as_base64(token)},
        metadata=V1ObjectMeta(
            name=tokens[0]["metadata"]["name"], namespace=namespace
        ),
        type="Opaque",
    )
    await core_api.replace_namespaced_secret(
        tokens[0]["metadata"]["name"], namespace, secret
    )

    # Replace the other token with a valid token with the wrong scopes.
    token = await token_service.create_token_from_admin_request(
        AdminTokenRequest(
            username=tokens[1]["spec"]["service"],
            token_type=TokenType.service,
            scopes=["read:all"],
        ),
        TokenData.internal_token(),
        ip_address=None,
    )
    secret = V1Secret(
        api_version="v1",
        kind="Secret",
        data={"token": token_as_base64(token)},
        metadata=V1ObjectMeta(
            name=tokens[1]["metadata"]["name"], namespace=namespace
        ),
        type="Opaque",
    )
    await core_api.replace_namespaced_secret(
        tokens[1]["metadata"]["name"], namespace, secret
    )

    # Run the operator again.  This should create new tokens for both.  We
    # need to wait for longer to ensure the timer runs, since the create and
    # update handlers will not notice a change.
    delay = KUBERNETES_TIMER_DELAY + 2
    await run_operator_once("gafaelfawr.operator", delay=delay)
    await assert_secrets_match(factory, api_client, tokens)
    nublado_secret = await core_api.read_namespaced_secret(
        tokens[1]["metadata"]["name"], namespace
    )

    # Finally, replace a secret with one with no token.
    secret = V1Secret(
        api_version="v1",
        data={},
        metadata=V1ObjectMeta(
            name=tokens[0]["metadata"]["name"], namespace=namespace
        ),
        type="Opaque",
    )
    await core_api.replace_namespaced_secret(
        tokens[0]["metadata"]["name"], namespace, secret
    )

    # Run the operator again.  This should create a new token for the first
    # secret but not for the second.
    await run_operator_once("gafaelfawr.operator", delay=delay)
    await assert_secrets_match(factory, api_client, tokens, is_fresh=False)
    assert nublado_secret == await core_api.read_namespaced_secret(
        tokens[1]["metadata"]["name"], namespace
    )


@requires_kubernetes
@pytest.mark.asyncio
async def test_update(
    factory: Factory, api_client: ApiClient, namespace: str
) -> None:
    core_api = client.CoreV1Api(api_client)
    custom_api = client.CustomObjectsApi(api_client)
    service_token = operator_test_input("tokens", namespace)[0]
    secret = operator_test_output("tokens", namespace)[0]

    # Start the operator.  Additional changes will be made while the operator
    # is running.
    with operator_running("gafaelfawr.operator"):
        await create_custom_resources(api_client, [service_token])
        await asyncio.sleep(1)
        await assert_resources_match(api_client, [secret])
        await assert_secrets_match(factory, api_client, [service_token])

        service_token = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawrservicetokens",
            service_token["metadata"]["name"],
        )
        service_token["spec"]["service"] = "bot-other-mobu"
        await custom_api.replace_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawrservicetokens",
            service_token["metadata"]["name"],
            service_token,
        )
        await asyncio.sleep(1)
        await assert_secrets_match(factory, api_client, [service_token])

        # Now add some labels and annotations.
        service_token = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawrservicetokens",
            service_token["metadata"]["name"],
        )
        service_token["metadata"]["labels"] = {"foo": "bar"}
        service_token["metadata"]["annotations"] = {"one": "1", "two": "2"}
        await custom_api.replace_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawrservicetokens",
            service_token["metadata"]["name"],
            service_token,
        )
        await asyncio.sleep(1)
        for key in ("annotations", "labels"):
            secret["metadata"][key] = service_token["metadata"][key]
        await assert_resources_match(api_client, [secret])

        # Deletion should remove the secret.  Wait a bit longer for this,
        # since it takes Kubernetes a while to finish deleting things.
        await custom_api.delete_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawrservicetokens",
            service_token["metadata"]["name"],
        )
        await asyncio.sleep(5)
        with pytest.raises(ApiException) as excinfo:
            await core_api.read_namespaced_secret(
                service_token["metadata"]["name"], namespace
            )
        assert excinfo.value.status == 404


@requires_kubernetes
@pytest.mark.asyncio
async def test_errors_scope(
    factory: Factory, api_client: ApiClient, namespace: str
) -> None:
    core_api = client.CoreV1Api(api_client)
    token = operator_test_input("token-error-scope", namespace)[0]
    name = token["metadata"]["name"]
    status = KubernetesResourceStatus(
        message="Unknown scopes requested",
        generation=ANY,
        reason=StatusReason.Failed,
        timestamp=ANY,
    )

    with operator_running("gafaelfawr.operator"):
        await create_custom_resources(api_client, [token])
        await asyncio.sleep(1)

    await assert_custom_resource_status_is(api_client, token, status)
    with pytest.raises(ApiException) as excinfo:
        await core_api.read_namespaced_secret(name, namespace)
    assert excinfo.value.status == 404


@requires_kubernetes
@pytest.mark.asyncio
async def test_errors_username(
    factory: Factory, api_client: ApiClient, namespace: str
) -> None:
    core_api = client.CoreV1Api(api_client)
    token = operator_test_input("token-error-username", namespace)[0]
    name = token["metadata"]["name"]
    status = KubernetesResourceStatus(
        message='Username "mobu" must start with "bot-"',
        generation=ANY,
        reason=StatusReason.Failed,
        timestamp=ANY,
    )

    with operator_running("gafaelfawr.operator"):
        await create_custom_resources(api_client, [token])
        await asyncio.sleep(1)

    await assert_custom_resource_status_is(api_client, token, status)
    with pytest.raises(ApiException) as excinfo:
        await core_api.read_namespaced_secret(name, namespace)
    assert excinfo.value.status == 404
