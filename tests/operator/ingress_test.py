"""Tests for Kubernetes ingress management."""

from __future__ import annotations

import asyncio
from unittest.mock import ANY

import pytest
from kubernetes_asyncio import client
from kubernetes_asyncio.client import ApiClient

from gafaelfawr.models.kubernetes import KubernetesResourceStatus, StatusReason

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


@requires_kubernetes
@pytest.mark.asyncio
async def test_create(api_client: ApiClient, namespace: str) -> None:
    ingresses = operator_test_input("ingresses", namespace)
    await create_custom_resources(api_client, ingresses)

    await run_operator_once("gafaelfawr.operator")

    expected = operator_test_output("ingresses", namespace)
    await assert_resources_match(api_client, expected)
    for ingress in ingresses:
        status = KubernetesResourceStatus(
            message="Ingress was created",
            generation=ANY,
            reason=StatusReason.Created,
            timestamp=ANY,
        )
        await assert_custom_resource_status_is(api_client, ingress, status)


@requires_kubernetes
@pytest.mark.asyncio
async def test_replace(api_client: ApiClient, namespace: str) -> None:
    ingress = operator_test_input("ingresses", namespace)[0]
    expected = operator_test_output("ingresses", namespace)[0]
    custom_api = client.CustomObjectsApi(api_client)

    with operator_running("gafaelfawr.operator"):
        await create_custom_resources(api_client, [ingress])
        await asyncio.sleep(1)

        await assert_resources_match(api_client, [expected])
        status = KubernetesResourceStatus(
            message="Ingress was created",
            generation=ANY,
            reason=StatusReason.Created,
            timestamp=ANY,
        )
        await assert_custom_resource_status_is(api_client, ingress, status)

        await custom_api.patch_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            ingress["metadata"]["name"],
            [{"op": "replace", "path": "/config/authType", "value": "basic"}],
        )
        await asyncio.sleep(1)

        expected["metadata"]["annotations"][
            "nginx.ingress.kubernetes.io/auth-url"
        ] = "https://foo.example.com/auth?scope=read%3Aall&auth_type=basic"
        await assert_resources_match(api_client, [expected])
        status.message = "Ingress was updated"
        status.reason = StatusReason.Updated
        await assert_custom_resource_status_is(api_client, ingress, status)

        ingress = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            ingress["metadata"]["name"],
        )
        ingress["config"]["authType"] = "bearer"
        ingress["config"]["loginRedirect"] = True
        await custom_api.replace_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            ingress["metadata"]["name"],
            ingress,
        )
        await asyncio.sleep(1)

        expected["metadata"]["annotations"][
            "nginx.ingress.kubernetes.io/auth-url"
        ] = "https://foo.example.com/auth?scope=read%3Aall&auth_type=bearer"
        expected["metadata"]["annotations"][
            "nginx.ingress.kubernetes.io/auth-signin"
        ] = "https://foo.example.com/login"
        await assert_resources_match(api_client, [expected])


@requires_kubernetes
@pytest.mark.asyncio
async def test_resume(api_client: ApiClient, namespace: str) -> None:
    """Test periodic rechecking of Ingress resources."""
    ingress = operator_test_input("ingresses", namespace)[0]
    expected = operator_test_output("ingresses", namespace)[0]
    networking_api = client.NetworkingV1Api(api_client)
    await create_custom_resources(api_client, [ingress])

    await run_operator_once("gafaelfawr.operator")
    await assert_resources_match(api_client, [expected])

    # Modify the Ingress but not the GafaelfawrIngress.
    name = expected["metadata"]["name"]
    generated = await networking_api.read_namespaced_ingress(name, namespace)
    generated.metadata.annotations = {}
    await networking_api.replace_namespaced_ingress(
        expected["metadata"]["name"], namespace, generated
    )

    # Run the operator again.  This should fix the modified ingress via the
    # resume event handler.
    await run_operator_once("gafaelfawr.operator")
    await assert_resources_match(api_client, [expected])
