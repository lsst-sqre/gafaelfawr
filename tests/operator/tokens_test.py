"""Tests for Kubernetes secret management."""

from __future__ import annotations

import asyncio
import os
from base64 import b64decode, b64encode
from datetime import timedelta
from typing import Any, Dict, List
from unittest.mock import ANY

import pytest
from kopf.testing import KopfRunner
from kubernetes_asyncio import client
from kubernetes_asyncio.client import (
    ApiClient,
    ApiException,
    V1ObjectMeta,
    V1OwnerReference,
    V1Secret,
)
from safir.testing.kubernetes import MockKubernetesApi

from gafaelfawr.factory import Factory
from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenType,
)
from gafaelfawr.services.token import TokenService
from gafaelfawr.storage.kubernetes import StatusReason
from gafaelfawr.util import current_datetime

from ..support.kubernetes import TEST_KUBERNETES_NAMESPACES

TEST_SERVICE_TOKENS: List[Dict[str, Any]] = [
    {
        "apiVersion": "gafaelfawr.lsst.io/v1alpha1",
        "kind": "GafaelfawrServiceToken",
        "metadata": {
            "name": "gafaelfawr-secret",
            "namespace": TEST_KUBERNETES_NAMESPACES[0],
        },
        "spec": {
            "service": "bot-mobu",
            "scopes": ["admin:token"],
        },
    },
    {
        "apiVersion": "gafaelfawr.lsst.io/v1alpha1",
        "kind": "GafaelfawrServiceToken",
        "metadata": {
            "name": "gafaelfawr",
            "namespace": TEST_KUBERNETES_NAMESPACES[1],
            "labels": {
                "foo": "bar",
                "other": "blah",
            },
            "annotations": {
                "argocd.argoproj.io/compare-options": "IgnoreExtraneous",
                "argocd.argoproj.io/sync-options": "Prune=false",
            },
        },
        "spec": {
            "service": "bot-nublado-hub",
            "scopes": [],
        },
    },
]

requires_kubernetes = pytest.mark.skipif(
    os.getenv("TEST_KUBERNETES") is None,
    reason="Install minikube and set TEST_KUBERNETES to run test",
)


async def create_test_service_tokens(kubernetes: ApiClient) -> None:
    custom_api = client.CustomObjectsApi(kubernetes)
    for body in TEST_SERVICE_TOKENS:
        await custom_api.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            body["metadata"]["namespace"],
            "gafaelfawrservicetokens",
            body,
        )


async def run_operator(*, delay: float = 1) -> None:
    kopf_command = [
        "run",
        "-A",
        "--verbose",
        "--log-format=json",
        "-m",
        "gafaelfawr.operator",
    ]
    with KopfRunner(kopf_command) as runner:
        await asyncio.sleep(delay)
    print(runner.stdout)
    assert runner.exit_code == 0
    assert runner.exception is None


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


async def assert_kubernetes_secrets_are_correct(
    factory: Factory, kubernetes: ApiClient, is_fresh: bool = True
) -> None:
    token_service = factory.create_token_service()

    # Get all of the GafaelfawrServiceToken custom objects.
    custom_api = client.CustomObjectsApi(kubernetes)
    service_tokens = []
    for namespace in TEST_KUBERNETES_NAMESPACES:
        token_list = await custom_api.list_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawrservicetokens",
        )
        service_tokens.extend(token_list["items"])

    # Calculate the expected secrets.  Convert empty annotations and labels to
    # None separately.
    expected = [
        V1Secret(
            data={"token": ANY},
            metadata=V1ObjectMeta(
                name=t["metadata"]["name"],
                namespace=t["metadata"]["namespace"],
                annotations={
                    k: v
                    for k, v in t["metadata"].get("annotations", {}).items()
                    if not k.startswith("kopf.zalando.org/")
                },
                creation_timestamp=ANY,
                labels=t["metadata"].get("labels", {}),
                managed_fields=ANY,
                owner_references=[
                    V1OwnerReference(
                        api_version="gafaelfawr.lsst.io/v1alpha1",
                        block_owner_deletion=True,
                        controller=True,
                        kind="GafaelfawrServiceToken",
                        name=t["metadata"]["name"],
                        uid=t["metadata"]["uid"],
                    ),
                ],
                resource_version=ANY,
                uid=ANY,
            ),
            type="Opaque",
        )
        for t in service_tokens
    ]
    for secret in expected:
        if secret.metadata.annotations == {}:
            secret.metadata.annotations = None
        if secret.metadata.labels == {}:
            secret.metadata.labels = None
    expected = sorted(
        expected, key=lambda o: (o.metadata.namespace, o.metadata.name)
    )
    core_api = client.CoreV1Api(kubernetes)
    secrets = []
    for namespace in (t["metadata"]["namespace"] for t in service_tokens):
        secret_list = await core_api.list_namespaced_secret(namespace)
        secrets.extend(
            [
                s
                for s in secret_list.items
                if not s.metadata.name.startswith("default")
            ]
        )
    assert secrets == expected

    # Now check that every token in those secrets is correct.
    for service_token in service_tokens:
        name = service_token["metadata"]["name"]
        namespace = service_token["metadata"]["namespace"]
        secret = await core_api.read_namespaced_secret(name, namespace)
        data = await token_data_from_secret(token_service, secret)
        assert data == TokenData(
            token=data.token,
            username=service_token["spec"]["service"],
            token_type=TokenType.service,
            scopes=service_token["spec"]["scopes"],
            created=data.created,
            expires=None,
            name=None,
            uid=None,
            groups=None,
        )
        if is_fresh:
            now = current_datetime()
            assert now - timedelta(seconds=10) <= data.created <= now


@requires_kubernetes
@pytest.mark.asyncio
async def test_create(factory: Factory, kubernetes: ApiClient) -> None:
    await create_test_service_tokens(kubernetes)

    await run_operator()
    await assert_kubernetes_secrets_are_correct(factory, kubernetes)

    custom_api = client.CustomObjectsApi(kubernetes)
    service_token = await custom_api.get_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        TEST_KUBERNETES_NAMESPACES[0],
        "gafaelfawrservicetokens",
        "gafaelfawr-secret",
    )
    assert service_token["status"] == {
        "create": {
            "lastTransitionTime": ANY,
            "message": "Secret was created",
            "observedGeneration": ANY,
            "reason": StatusReason.Created.value,
            "status": "True",
            "type": "SecretCreated",
        }
    }
    service_token = await custom_api.get_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        TEST_KUBERNETES_NAMESPACES[1],
        "gafaelfawrservicetokens",
        "gafaelfawr",
    )
    assert service_token["status"] == {
        "create": {
            "lastTransitionTime": ANY,
            "message": "Secret was created",
            "observedGeneration": ANY,
            "reason": StatusReason.Created.value,
            "status": "True",
            "type": "SecretCreated",
        }
    }


@requires_kubernetes
@pytest.mark.asyncio
async def test_secret_verification(
    factory: Factory, kubernetes: ApiClient
) -> None:
    await create_test_service_tokens(kubernetes)
    token_service = factory.create_token_service()
    core_api = client.CoreV1Api(kubernetes)

    # Valid secret but with a bogus token.
    secret = V1Secret(
        api_version="v1",
        kind="Secret",
        data={"token": b64encode(b"bogus").decode()},
        metadata=V1ObjectMeta(
            name="gafaelfawr-secret", namespace=TEST_KUBERNETES_NAMESPACES[0]
        ),
        type="Opaque",
    )
    await core_api.create_namespaced_secret(
        TEST_KUBERNETES_NAMESPACES[0], secret
    )

    # Valid secret but with a nonexistent token.
    secret = V1Secret(
        api_version="v1",
        kind="Secret",
        data={"token": token_as_base64(Token())},
        metadata=V1ObjectMeta(
            name="gafaelfawr",
            namespace=TEST_KUBERNETES_NAMESPACES[1],
            labels={
                "foo": "bar",
                "other": "blah",
            },
            annotations={
                "argocd.argoproj.io/compare-options": "IgnoreExtraneous",
                "argocd.argoproj.io/sync-options": "Prune=false",
            },
        ),
        type="Opaque",
    )
    await core_api.create_namespaced_secret(
        TEST_KUBERNETES_NAMESPACES[1], secret
    )

    # Run the operator.  This should replace both with fresh secrets.
    await run_operator()
    await assert_kubernetes_secrets_are_correct(factory, kubernetes)

    # Replace one secret with a valid token for the wrong service.
    async with factory.session.begin():
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
            name="gafaelfawr-secret", namespace=TEST_KUBERNETES_NAMESPACES[0]
        ),
        type="Opaque",
    )
    await core_api.replace_namespaced_secret(
        "gafaelfawr-secret", TEST_KUBERNETES_NAMESPACES[0], secret
    )

    # Replace the other token with a valid token with the wrong scopes.
    async with factory.session.begin():
        token = await token_service.create_token_from_admin_request(
            AdminTokenRequest(
                username="bot-nublado-hub",
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
            name="gafaelfawr", namespace=TEST_KUBERNETES_NAMESPACES[1]
        ),
        type="Opaque",
    )
    await core_api.replace_namespaced_secret(
        "gafaelfawr", TEST_KUBERNETES_NAMESPACES[1], secret
    )

    # Run the operator again.  This should create new tokens for both.  We
    # need to wait for longer to ensure the timer runs, since the create and
    # update handlers will not notice a change.
    await run_operator(delay=10)
    await assert_kubernetes_secrets_are_correct(factory, kubernetes)
    nublado_secret = await core_api.read_namespaced_secret(
        "gafaelfawr", TEST_KUBERNETES_NAMESPACES[1]
    )

    # Finally, replace a secret with one with no token.
    secret = V1Secret(
        api_version="v1",
        data={},
        metadata=V1ObjectMeta(
            name="gafaelfawr-secret", namespace=TEST_KUBERNETES_NAMESPACES[0]
        ),
        type="Opaque",
    )
    await core_api.replace_namespaced_secret(
        "gafaelfawr-secret", TEST_KUBERNETES_NAMESPACES[0], secret
    )

    # Run the operator again.  This should create a new token for the first
    # secret but not for the second.
    await run_operator(delay=10)
    await assert_kubernetes_secrets_are_correct(
        factory, kubernetes, is_fresh=False
    )
    assert nublado_secret == await core_api.read_namespaced_secret(
        "gafaelfawr", TEST_KUBERNETES_NAMESPACES[1]
    )


@requires_kubernetes
@pytest.mark.asyncio
async def test_update(factory: Factory, kubernetes: ApiClient) -> None:
    core_api = client.CoreV1Api(kubernetes)
    custom_api = client.CustomObjectsApi(kubernetes)
    service_token: Dict[str, Any] = {
        "apiVersion": "gafaelfawr.lsst.io/v1alpha1",
        "kind": "GafaelfawrServiceToken",
        "metadata": {
            "name": "gafaelfawr-secret",
            "namespace": TEST_KUBERNETES_NAMESPACES[0],
        },
        "spec": {
            "service": "bot-mobu",
            "scopes": ["admin:token"],
        },
    }

    # Start the operator.  Additional changes will be made while the operator
    # is running.
    kopf_command = [
        "run",
        "-A",
        "--verbose",
        "--log-format=json",
        "-m",
        "gafaelfawr.operator",
    ]
    with KopfRunner(kopf_command) as runner:
        await custom_api.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            service_token,
        )
        await asyncio.sleep(1)
        await assert_kubernetes_secrets_are_correct(factory, kubernetes)

        service_token = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            "gafaelfawr-secret",
        )
        service_token["spec"]["service"] = "bot-other-mobu"
        await custom_api.replace_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            "gafaelfawr-secret",
            service_token,
        )
        await asyncio.sleep(1)
        await assert_kubernetes_secrets_are_correct(factory, kubernetes)

        # Now add some labels and annotations.
        service_token = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            "gafaelfawr-secret",
        )
        service_token["metadata"]["labels"] = {"foo": "bar"}
        service_token["metadata"]["annotations"] = {"one": "1", "two": "2"}
        await custom_api.replace_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            "gafaelfawr-secret",
            service_token,
        )
        await asyncio.sleep(1)
        await assert_kubernetes_secrets_are_correct(factory, kubernetes)

        # Deletion should remove the secret.
        await custom_api.delete_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            "gafaelfawr-secret",
        )
        await asyncio.sleep(5)
        with pytest.raises(ApiException) as excinfo:
            await core_api.read_namespaced_secret(
                "gafaelfawr-secret", TEST_KUBERNETES_NAMESPACES[0]
            )
        assert excinfo.value.status == 404

    print(runner.stdout)
    assert runner.exit_code == 0
    assert runner.exception is None


@requires_kubernetes
@pytest.mark.asyncio
async def test_errors_scope(
    factory: Factory, kubernetes: MockKubernetesApi
) -> None:
    core_api = client.CoreV1Api(kubernetes)
    custom_api = client.CustomObjectsApi(kubernetes)
    kopf_command = [
        "run",
        "-A",
        "--verbose",
        "--log-format=json",
        "-m",
        "gafaelfawr.operator",
    ]
    with KopfRunner(kopf_command) as runner:
        await custom_api.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            {
                "apiVersion": "gafaelfawr.lsst.io/v1alpha1",
                "kind": "GafaelfawrServiceToken",
                "metadata": {
                    "name": "gafaelfawr-secret",
                    "namespace": TEST_KUBERNETES_NAMESPACES[0],
                },
                "spec": {
                    "service": "bot-mobu",
                    "scopes": ["invalid:scope"],
                },
            },
        )

        await asyncio.sleep(1)
        with pytest.raises(ApiException) as excinfo:
            await core_api.read_namespaced_secret(
                "gafaelfawr-secret", TEST_KUBERNETES_NAMESPACES[0]
            )
        assert excinfo.value.status == 404
        service_token = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            "gafaelfawr-secret",
        )
        assert service_token["status"] == {
            "create": {
                "lastTransitionTime": ANY,
                "message": "Unknown scopes requested",
                "observedGeneration": 1,
                "reason": StatusReason.Failed.value,
                "status": "False",
                "type": "SecretCreated",
            }
        }

        # Fix the scope so that it can be successfully processed, since
        # otherwise Kopf blocks deletion of the namespace.
        service_token["spec"]["scopes"] = []
        await custom_api.replace_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            "gafaelfawr-secret",
            service_token,
        )
        await asyncio.sleep(1)

    print(runner.stdout)
    assert runner.exit_code == 0
    assert runner.exception is None


@requires_kubernetes
@pytest.mark.asyncio
async def test_errors_username(
    factory: Factory, kubernetes: ApiClient
) -> None:
    core_api = client.CoreV1Api(kubernetes)
    custom_api = client.CustomObjectsApi(kubernetes)
    kopf_command = [
        "run",
        "-A",
        "--verbose",
        "--log-format=json",
        "-m",
        "gafaelfawr.operator",
    ]
    with KopfRunner(kopf_command) as runner:
        await custom_api.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            {
                "apiVersion": "gafaelfawr.lsst.io/v1alpha1",
                "kind": "GafaelfawrServiceToken",
                "metadata": {
                    "name": "gafaelfawr-secret",
                    "namespace": TEST_KUBERNETES_NAMESPACES[0],
                },
                "spec": {
                    "service": "mobu",
                    "scopes": [],
                },
            },
        )

        await asyncio.sleep(1)
        with pytest.raises(ApiException) as excinfo:
            await core_api.read_namespaced_secret(
                "gafaelfawr-secret", TEST_KUBERNETES_NAMESPACES[0]
            )
        assert excinfo.value.status == 404
        service_token = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            "gafaelfawr-secret",
        )
        assert service_token["status"] == {
            "create": {
                "lastTransitionTime": ANY,
                "message": 'Username "mobu" must start with "bot-"',
                "observedGeneration": 1,
                "reason": StatusReason.Failed.value,
                "status": "False",
                "type": "SecretCreated",
            }
        }

        # Fix the scope so that it can be successfully processed, since
        # otherwise Kopf blocks deletion of the namespace.
        service_token["spec"]["service"] = "bot-mobu"
        await custom_api.replace_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            TEST_KUBERNETES_NAMESPACES[0],
            "gafaelfawrservicetokens",
            service_token["metadata"]["name"],
            service_token,
        )
        await asyncio.sleep(1)

    print(runner.stdout)
    assert runner.exit_code == 0
    assert runner.exception is None
