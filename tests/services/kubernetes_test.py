"""Tests for Kubernetes secret management."""

from __future__ import annotations

from base64 import b64decode, b64encode
from datetime import timedelta
from queue import Queue
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest
from kubernetes.client import (
    ApiException,
    V1ObjectMeta,
    V1OwnerReference,
    V1Secret,
)

from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenType,
)
from gafaelfawr.storage.kubernetes import (
    StatusReason,
    WatchEvent,
    WatchEventType,
)
from gafaelfawr.util import current_datetime
from tests.support.kubernetes import (
    MockKubernetesApi,
    assert_kubernetes_objects_are,
)
from tests.support.logging import parse_log

if TYPE_CHECKING:
    from typing import Any, Dict, List

    from _pytest.logging import LogCaptureFixture

    from gafaelfawr.factory import ComponentFactory
    from gafaelfawr.services.token import TokenService

TEST_SERVICE_TOKENS: List[Dict[str, Any]] = [
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
    {
        "apiVersion": "gafaelfawr.lsst.io/v1alpha1",
        "kind": "GafaelfawrServiceToken",
        "metadata": {
            "name": "gafaelfawr",
            "namespace": "nublado2",
            "generation": 45,
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
            "service": "nublado-hub",
            "scopes": [],
        },
    },
]


def create_test_service_tokens(mock: MockKubernetesApi) -> None:
    for body in TEST_SERVICE_TOKENS:
        mock.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            body["metadata"]["namespace"],
            "gafaelfawrservicetokens",
            body,
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


async def assert_kubernetes_secrets_are_correct(
    factory: ComponentFactory, mock: MockKubernetesApi, is_fresh: bool = True
) -> None:
    token_service = factory.create_token_service()

    # Get all of the GafaelfawrServiceToken custom objects.
    service_tokens = mock.get_all_objects_for_test("GafaelfawrServiceToken")

    # Calculate the expected secrets.
    expected = [
        V1Secret(
            api_version="v1",
            kind="Secret",
            data={"token": ANY},
            metadata=V1ObjectMeta(
                name=t["metadata"]["name"],
                namespace=t["metadata"]["namespace"],
                annotations=t["metadata"].get("annotations", {}),
                labels=t["metadata"].get("labels", {}),
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
            ),
            type="Opaque",
        )
        for t in service_tokens
    ]
    assert_kubernetes_objects_are(mock, "Secret", expected)

    # Now check that every token in those secrets is correct.
    for service_token in service_tokens:
        name = service_token["metadata"]["name"]
        namespace = service_token["metadata"]["namespace"]
        secret = mock.read_namespaced_secret(name, namespace)
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
            assert now - timedelta(seconds=5) <= data.created <= now


@pytest.mark.asyncio
async def test_create(
    factory: ComponentFactory,
    mock_kubernetes: MockKubernetesApi,
    caplog: LogCaptureFixture,
) -> None:
    create_test_service_tokens(mock_kubernetes)
    kubernetes_service = factory.create_kubernetes_service()
    await kubernetes_service.update_service_tokens()
    await assert_kubernetes_secrets_are_correct(factory, mock_kubernetes)

    service_token = mock_kubernetes.get_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        "gafaelfawr-secret",
    )
    assert service_token["status"]["conditions"] == [
        {
            "lastTransitionTime": ANY,
            "message": "Secret was created",
            "observedGeneration": 1,
            "reason": StatusReason.Created.value,
            "status": "True",
            "type": "SecretCreated",
        }
    ]
    service_token = mock_kubernetes.get_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "nublado2",
        "gafaelfawrservicetokens",
        "gafaelfawr",
    )
    assert service_token["status"]["conditions"] == [
        {
            "lastTransitionTime": ANY,
            "message": "Secret was created",
            "observedGeneration": 45,
            "reason": StatusReason.Created.value,
            "status": "True",
            "type": "SecretCreated",
        }
    ]

    assert parse_log(caplog) == [
        {
            "event": "Created new service token",
            "key": ANY,
            "level": "info",
            "token_scope": "admin:token",
            "token_username": "mobu",
        },
        {
            "event": "Created mobu/gafaelfawr-secret secret",
            "level": "info",
            "scopes": ["admin:token"],
            "service": "mobu",
        },
        {
            "event": "Created new service token",
            "key": ANY,
            "level": "info",
            "token_scope": "",
            "token_username": "nublado-hub",
        },
        {
            "event": "Created nublado2/gafaelfawr secret",
            "level": "info",
            "scopes": [],
            "service": "nublado-hub",
        },
    ]

    # Running creation again should not change anything.
    caplog.clear()
    objects = mock_kubernetes.get_all_objects_for_test("Secret")
    await kubernetes_service.update_service_tokens()
    assert mock_kubernetes.get_all_objects_for_test("Secret") == objects
    assert caplog.record_tuples == []


@pytest.mark.asyncio
async def test_modify(
    factory: ComponentFactory,
    mock_kubernetes: MockKubernetesApi,
    caplog: LogCaptureFixture,
) -> None:
    create_test_service_tokens(mock_kubernetes)
    kubernetes_service = factory.create_kubernetes_service()
    token_service = factory.create_token_service()

    # Valid secret but with a bogus token.
    secret = V1Secret(
        api_version="v1",
        kind="Secret",
        data={"token": "bogus"},
        metadata=V1ObjectMeta(name="gafaelfawr-secret", namespace="mobu"),
        type="Opaque",
    )
    mock_kubernetes.create_namespaced_secret("mobu", secret)

    # Valid secret but with a nonexistent token.
    secret = V1Secret(
        api_version="v1",
        kind="Secret",
        data={"token": token_as_base64(Token())},
        metadata=V1ObjectMeta(
            name="gafaelfawr",
            namespace="nublado2",
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
    mock_kubernetes.create_namespaced_secret("nublado2", secret)

    # Update the secrets.  This should replace both with fresh secrets.
    await kubernetes_service.update_service_tokens()
    await assert_kubernetes_secrets_are_correct(factory, mock_kubernetes)

    # Check the logging.
    assert parse_log(caplog) == [
        {
            "event": "Created new service token",
            "key": ANY,
            "level": "info",
            "token_scope": "admin:token",
            "token_username": "mobu",
        },
        {
            "event": "Updated mobu/gafaelfawr-secret secret",
            "level": "info",
            "scopes": ["admin:token"],
            "service": "mobu",
        },
        {
            "event": "Created new service token",
            "key": ANY,
            "level": "info",
            "token_scope": "",
            "token_username": "nublado-hub",
        },
        {
            "event": "Updated nublado2/gafaelfawr secret",
            "level": "info",
            "scopes": [],
            "service": "nublado-hub",
        },
    ]

    # Replace one secret with a valid token for the wrong service.
    async with factory.session.begin():
        token = await token_service.create_token_from_admin_request(
            AdminTokenRequest(
                username="some-other-service",
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
        metadata=V1ObjectMeta(name="gafaelfawr-secret", namespace="mobu"),
        type="Opaque",
    )
    mock_kubernetes.replace_namespaced_secret(
        "gafaelfawr-secret", "mobu", secret
    )

    # Replace the other token with a valid token with the wrong scopes.
    async with factory.session.begin():
        token = await token_service.create_token_from_admin_request(
            AdminTokenRequest(
                username="nublado-hub",
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
        metadata=V1ObjectMeta(name="gafaelfawr", namespace="nublado2"),
        type="Opaque",
    )
    mock_kubernetes.replace_namespaced_secret("gafaelfawr", "nublado2", secret)

    # Update the secrets.  This should create new tokens for both.
    await kubernetes_service.update_service_tokens()
    await assert_kubernetes_secrets_are_correct(factory, mock_kubernetes)
    nublado_secret = mock_kubernetes.read_namespaced_secret(
        "gafaelfawr", "nublado2"
    )

    # Finally, replace a secret with one with no token.
    secret = V1Secret(
        api_version="v1",
        data={},
        metadata=V1ObjectMeta(name="gafaelfawr-secret", namespace="mobu"),
        type="Opaque",
    )
    mock_kubernetes.replace_namespaced_secret(
        "gafaelfawr-secret", "mobu", secret
    )

    # Update the secrets.  This should create a new token for the first secret
    # but not for the second.
    await kubernetes_service.update_service_tokens()
    await assert_kubernetes_secrets_are_correct(
        factory, mock_kubernetes, is_fresh=False
    )
    assert nublado_secret == mock_kubernetes.read_namespaced_secret(
        "gafaelfawr", "nublado2"
    )


@pytest.mark.asyncio
async def test_update_from_queue(
    factory: ComponentFactory, mock_kubernetes: MockKubernetesApi
) -> None:
    service_token: Dict[str, Any] = {
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
    }
    mock_kubernetes.create_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        service_token,
    )
    kubernetes_service = factory.create_kubernetes_service()
    queue: Queue[WatchEvent] = Queue()
    queue.put(
        WatchEvent(
            event_type=WatchEventType.ADDED,
            name="gafaelfawr-secret",
            namespace="mobu",
            generation=1,
        )
    )
    await kubernetes_service.update_service_tokens_from_queue(
        queue, exit_on_empty=True
    )
    await assert_kubernetes_secrets_are_correct(factory, mock_kubernetes)
    assert queue.empty()

    service_token = mock_kubernetes.get_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        "gafaelfawr-secret",
    )
    service_token["metadata"]["generation"] = 2
    service_token["spec"]["service"] = "other-mobu"
    mock_kubernetes.replace_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        "gafaelfawr-secret",
        service_token,
    )
    queue.put(
        WatchEvent(
            event_type=WatchEventType.MODIFIED,
            name="gafaelfawr-secret",
            namespace="mobu",
            generation=2,
        )
    )
    await kubernetes_service.update_service_tokens_from_queue(
        queue, exit_on_empty=True
    )
    await assert_kubernetes_secrets_are_correct(factory, mock_kubernetes)
    assert queue.empty()

    # Deletion does nothing, but shouldn't prompt an error.
    queue.put(
        WatchEvent(
            event_type=WatchEventType.MODIFIED,
            name="gafaelfawr-secret",
            namespace="mobu",
            generation=2,
        )
    )
    await kubernetes_service.update_service_tokens_from_queue(
        queue, exit_on_empty=True
    )
    await assert_kubernetes_secrets_are_correct(factory, mock_kubernetes)
    assert queue.empty()


@pytest.mark.asyncio
async def test_update_generation(
    factory: ComponentFactory, mock_kubernetes: MockKubernetesApi
) -> None:
    """Test that GafaelfawrServiceToken status changes don't trigger updates.

    We always modify the GafaelfawrServiceToken on successful or failed
    changes to its associated Secret, but that in turn triggers another MODIFY
    watch message.  We don't want to act on that MODIFY because, if the Secret
    creation is failing, we could get into an infinite loop.

    This test verifies that we observe the generation for which we last
    processed an update and decline to attempt another update unless the
    generation changes.
    """
    service_token: Dict[str, Any] = {
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
    }
    mock_kubernetes.create_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        service_token,
    )
    kubernetes_service = factory.create_kubernetes_service()
    queue: Queue[WatchEvent] = Queue()
    queue.put(
        WatchEvent(
            event_type=WatchEventType.ADDED,
            name="gafaelfawr-secret",
            namespace="mobu",
            generation=1,
        )
    )
    await kubernetes_service.update_service_tokens_from_queue(
        queue, exit_on_empty=True
    )
    await assert_kubernetes_secrets_are_correct(factory, mock_kubernetes)
    assert queue.empty()
    secret = mock_kubernetes.read_namespaced_secret(
        "gafaelfawr-secret", "mobu"
    )
    assert secret

    # Modify the GafaelfawrServiceToken without changing the generation.  The
    # modify event should then be ignored.
    service_token = mock_kubernetes.get_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        "gafaelfawr-secret",
    )
    service_token["spec"]["service"] = "other-mobu"
    mock_kubernetes.replace_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        "gafaelfawr-secret",
        service_token,
    )
    queue.put(
        WatchEvent(
            event_type=WatchEventType.ADDED,
            name="gafaelfawr-secret",
            namespace="mobu",
            generation=1,
        )
    )
    await kubernetes_service.update_service_tokens_from_queue(
        queue, exit_on_empty=True
    )
    assert queue.empty()
    assert secret == mock_kubernetes.read_namespaced_secret(
        "gafaelfawr-secret", "mobu"
    )

    # But if we send a delete and then an add with the same generation, it
    # should be processed.
    queue.put(
        WatchEvent(
            event_type=WatchEventType.DELETED,
            name="gafaelfawr-secret",
            namespace="mobu",
            generation=1,
        )
    )
    queue.put(
        WatchEvent(
            event_type=WatchEventType.ADDED,
            name="gafaelfawr-secret",
            namespace="mobu",
            generation=1,
        )
    )
    await kubernetes_service.update_service_tokens_from_queue(
        queue, exit_on_empty=True
    )
    assert queue.empty()
    assert secret != mock_kubernetes.read_namespaced_secret(
        "gafaelfawr-secret", "mobu"
    )
    await assert_kubernetes_secrets_are_correct(factory, mock_kubernetes)


@pytest.mark.asyncio
async def test_update_metadata(
    factory: ComponentFactory, mock_kubernetes: MockKubernetesApi
) -> None:
    """Test that Secret metadata is updated even if generation doesn't change.

    Updates to metadata doesn't trigger a generation bump (since generation is
    in metadata itself), so propagating metadata to secrets has to be handled
    specially.
    """
    service_token: Dict[str, Any] = {
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
    }
    mock_kubernetes.create_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        service_token,
    )
    kubernetes_service = factory.create_kubernetes_service()
    await kubernetes_service.update_service_tokens()
    await assert_kubernetes_secrets_are_correct(factory, mock_kubernetes)
    secret = mock_kubernetes.read_namespaced_secret(
        "gafaelfawr-secret", "mobu"
    )
    assert secret

    # Sending a modified event does nothing.
    queue: Queue[WatchEvent] = Queue()
    queue.put(
        WatchEvent(
            event_type=WatchEventType.MODIFIED,
            name="gafaelfawr-secret",
            namespace="mobu",
            generation=1,
        )
    )
    await kubernetes_service.update_service_tokens_from_queue(
        queue, exit_on_empty=True
    )
    assert queue.empty()
    assert secret == mock_kubernetes.read_namespaced_secret(
        "gafaelfawr-secret", "mobu"
    )

    # Now add some labels and annotations.
    service_token = mock_kubernetes.get_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        "gafaelfawr-secret",
    )
    service_token["metadata"]["labels"] = {"foo": "bar"}
    service_token["metadata"]["annotations"] = {"one": "1", "two": "2"}
    mock_kubernetes.replace_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        "gafaelfawr-secret",
        service_token,
    )
    queue.put(
        WatchEvent(
            event_type=WatchEventType.MODIFIED,
            name="gafaelfawr-secret",
            namespace="mobu",
            generation=1,
        )
    )
    await kubernetes_service.update_service_tokens_from_queue(
        queue, exit_on_empty=True
    )
    assert queue.empty()
    await assert_kubernetes_secrets_are_correct(factory, mock_kubernetes)


@pytest.mark.asyncio
async def test_errors_replace_read(
    factory: ComponentFactory, mock_kubernetes: MockKubernetesApi
) -> None:
    create_test_service_tokens(mock_kubernetes)
    kubernetes_service = factory.create_kubernetes_service()
    token_service = factory.create_token_service()

    # Create a secret that should exist but has an invalid token.
    secret = V1Secret(
        api_version="v1",
        data={"token": token_as_base64(Token())},
        metadata=V1ObjectMeta(name="gafaelfawr-secret", namespace="mobu"),
        type="Opaque",
    )
    mock_kubernetes.create_namespaced_secret("mobu", secret)

    # Simulate some errors.  The callback function takes the operation and the
    # secret name.
    def error_callback_replace(method: str, *args: Any) -> None:
        if method in ("replace_namespaced_secret"):
            raise ApiException(status=500, reason="Some error")

    mock_kubernetes.error_callback = error_callback_replace

    # Now run the synchronization.  The secret should be left unchanged, but
    # we should still create the missing nublado2 secret.
    await kubernetes_service.update_service_tokens()
    objects = mock_kubernetes.get_all_objects_for_test("Secret")
    assert secret in objects
    good_secret = mock_kubernetes.read_namespaced_secret(
        "gafaelfawr", "nublado2"
    )
    assert await token_data_from_secret(token_service, good_secret)

    # We should have also updated the status of the parent custom object.
    service_token = mock_kubernetes.get_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        "gafaelfawr-secret",
    )
    assert service_token["status"]["conditions"] == [
        {
            "lastTransitionTime": ANY,
            "message": "Kubernetes API error: (500)\nReason: Some error\n",
            "observedGeneration": 1,
            "reason": StatusReason.Failed.value,
            "status": "False",
            "type": "SecretCreated",
        }
    ]

    # Try again, but simulating an error in retrieving a secret.
    def error_callback_read(method: str, *args: Any) -> None:
        if method == "read_namespaced_secret":
            raise ApiException(status=500, reason="Some error")

    mock_kubernetes.error_callback = error_callback_read

    # Now run the synchronization.  As before, the secret should be left
    # unchanged, and the good secret should also be left unchanged.
    await kubernetes_service.update_service_tokens()
    objects = mock_kubernetes.get_all_objects_for_test("Secret")
    assert secret in objects


@pytest.mark.asyncio
async def test_errors_scope(
    factory: ComponentFactory, mock_kubernetes: MockKubernetesApi
) -> None:
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
                "scopes": ["invalid:scope"],
            },
        },
    )
    kubernetes_service = factory.create_kubernetes_service()

    await kubernetes_service.update_service_tokens()
    with pytest.raises(ApiException):
        mock_kubernetes.read_namespaced_secret("gafaelfawr-secret", "mobu")
    service_token = mock_kubernetes.get_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        "mobu",
        "gafaelfawrservicetokens",
        "gafaelfawr-secret",
    )
    assert service_token["status"]["conditions"] == [
        {
            "lastTransitionTime": ANY,
            "message": "Unknown scopes requested",
            "observedGeneration": 1,
            "reason": StatusReason.Failed.value,
            "status": "False",
            "type": "SecretCreated",
        }
    ]
