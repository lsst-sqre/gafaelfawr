"""Tests for Kubernetes ingress management."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import ANY

import pytest
from kubernetes_asyncio import client
from kubernetes_asyncio.client import (
    ApiClient,
    V1HTTPIngressPath,
    V1HTTPIngressRuleValue,
    V1Ingress,
    V1IngressBackend,
    V1IngressRule,
    V1IngressServiceBackend,
    V1IngressSpec,
    V1IngressTLS,
    V1ObjectMeta,
    V1OwnerReference,
    V1ServiceBackendPort,
)

from gafaelfawr.models.kubernetes import StatusReason

from ..support.kubernetes import operator_running, requires_kubernetes

_SMALL_INGRESS: dict[str, Any] = {
    "apiVersion": "gafaelfawr.lsst.io/v1alpha1",
    "kind": "GafaelfawrIngress",
    "metadata": {"name": "small-ingress"},
    "config": {
        "baseUrl": "https://foo.example.com",
        "scopes": {"all": ["read:all"]},
    },
    "template": {
        "metadata": {"name": "small"},
        "spec": {
            "rules": [
                {
                    "host": "foo.example.com",
                    "http": {
                        "paths": [
                            {
                                "path": "/foo",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": "something",
                                        "port": {"name": "http"},
                                    }
                                },
                            }
                        ]
                    },
                }
            ],
        },
    },
}


@requires_kubernetes
@pytest.mark.asyncio
async def test_create(api_client: ApiClient, namespace: str) -> None:
    custom_api = client.CustomObjectsApi(api_client)
    networking_api = client.NetworkingV1Api(api_client)

    with operator_running("gafaelfawr.operator"):
        await custom_api.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            _SMALL_INGRESS,
        )
        await custom_api.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            {
                "apiVersion": "gafaelfawr.lsst.io/v1alpha1",
                "kind": "GafaelfawrIngress",
                "metadata": {
                    "name": "notebook-ingress",
                    "namespace": namespace,
                },
                "config": {
                    "baseUrl": "https://foo.example.com",
                    "scopes": {"any": ["read:all"]},
                    "authType": "basic",
                    "loginRedirect": True,
                    "replace403": True,
                    "delegate": {
                        "notebook": {},
                        "minimumLifetime": 600,
                    },
                },
                "template": {
                    "metadata": {"name": "notebook"},
                    "spec": {
                        "rules": [
                            {
                                "host": "foo.example.com",
                                "http": {
                                    "paths": [
                                        {
                                            "path": "/bar",
                                            "pathType": "Exact",
                                            "backend": {
                                                "service": {
                                                    "name": "something",
                                                    "port": {"number": 80},
                                                }
                                            },
                                        }
                                    ]
                                },
                            }
                        ],
                        "tls": [
                            {
                                "hosts": ["foo.example.com"],
                                "secretName": "tls-secret",
                            }
                        ],
                    },
                },
            },
        )
        await custom_api.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            {
                "apiVersion": "gafaelfawr.lsst.io/v1alpha1",
                "kind": "GafaelfawrIngress",
                "metadata": {
                    "name": "internal-ingress",
                    "namespace": namespace,
                },
                "config": {
                    "baseUrl": "https://foo.example.com",
                    "scopes": {"all": ["read:all", "read:some"]},
                    "delegate": {
                        "internal": {
                            "service": "some-service",
                            "scopes": ["read:all", "read:some"],
                        },
                    },
                },
                "template": {
                    "metadata": {"name": "internal"},
                    "spec": {
                        "rules": [
                            {
                                "host": "foo.example.com",
                                "http": {
                                    "paths": [
                                        {
                                            "path": "/baz",
                                            "pathType": (
                                                "ImplementationSpecific"
                                            ),
                                            "backend": {
                                                "service": {
                                                    "name": "something",
                                                    "port": {"number": 80},
                                                }
                                            },
                                        }
                                    ]
                                },
                            }
                        ],
                    },
                },
            },
        )
        small_ingress = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            "small-ingress",
        )
        notebook_ingress = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            "notebook-ingress",
        )
        internal_ingress = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            "internal-ingress",
        )
        await asyncio.sleep(1)

        ingress = await networking_api.read_namespaced_ingress(
            "small", namespace
        )
        expected = V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=V1ObjectMeta(
                name="small",
                namespace=namespace,
                annotations={
                    "nginx.ingress.kubernetes.io/auth-method": "GET",
                    "nginx.ingress.kubernetes.io/auth-response-headers": (
                        "X-Auth-Request-Email,X-Auth-Request-User"
                    ),
                    "nginx.ingress.kubernetes.io/auth-url": (
                        "https://foo.example.com/auth?scope=read%3Aall"
                    ),
                },
                creation_timestamp=ANY,
                generation=ANY,
                managed_fields=ANY,
                owner_references=[
                    V1OwnerReference(
                        api_version="gafaelfawr.lsst.io/v1alpha1",
                        block_owner_deletion=True,
                        controller=True,
                        kind="GafaelfawrIngress",
                        name="small-ingress",
                        uid=small_ingress["metadata"]["uid"],
                    )
                ],
                resource_version=ANY,
                uid=ANY,
            ),
            spec=V1IngressSpec(
                ingress_class_name="nginx",
                rules=[
                    V1IngressRule(
                        host="foo.example.com",
                        http=V1HTTPIngressRuleValue(
                            paths=[
                                V1HTTPIngressPath(
                                    path="/foo",
                                    path_type="Prefix",
                                    backend=V1IngressBackend(
                                        service=V1IngressServiceBackend(
                                            name="something",
                                            port=V1ServiceBackendPort(
                                                name="http"
                                            ),
                                        )
                                    ),
                                )
                            ]
                        ),
                    )
                ],
            ),
            status=ANY,
        )
        assert ingress.to_dict() == expected.to_dict()

        ingress = await networking_api.read_namespaced_ingress(
            "notebook", namespace
        )
        expected = V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=V1ObjectMeta(
                name="notebook",
                namespace=namespace,
                annotations={
                    "nginx.ingress.kubernetes.io/auth-method": "GET",
                    "nginx.ingress.kubernetes.io/auth-response-headers": (
                        "X-Auth-Request-Email,X-Auth-Request-User"
                        ",X-Auth-Request-Token"
                    ),
                    "nginx.ingress.kubernetes.io/auth-signin": (
                        "https://foo.example.com/login"
                    ),
                    "nginx.ingress.kubernetes.io/auth-url": (
                        "https://foo.example.com/auth?scope=read%3Aall"
                        "&satisfy=any&notebook=true&minimum_lifetime=600"
                        "&auth_type=basic"
                    ),
                    "nginx.ingress.kubernetes.io/configuration-snippet": (
                        'error_page 403 = "/auth/forbidden?scope=read%3Aall'
                        "&satisfy=any&notebook=true&minimum_lifetime=600"
                        '&auth_type=basic";'
                    ),
                },
                creation_timestamp=ANY,
                generation=ANY,
                managed_fields=ANY,
                owner_references=[
                    V1OwnerReference(
                        api_version="gafaelfawr.lsst.io/v1alpha1",
                        block_owner_deletion=True,
                        controller=True,
                        kind="GafaelfawrIngress",
                        name="notebook-ingress",
                        uid=notebook_ingress["metadata"]["uid"],
                    )
                ],
                resource_version=ANY,
                uid=ANY,
            ),
            spec=V1IngressSpec(
                ingress_class_name="nginx",
                rules=[
                    V1IngressRule(
                        host="foo.example.com",
                        http=V1HTTPIngressRuleValue(
                            paths=[
                                V1HTTPIngressPath(
                                    path="/bar",
                                    path_type="Exact",
                                    backend=V1IngressBackend(
                                        service=V1IngressServiceBackend(
                                            name="something",
                                            port=V1ServiceBackendPort(
                                                number=80
                                            ),
                                        )
                                    ),
                                )
                            ]
                        ),
                    )
                ],
                tls=[
                    V1IngressTLS(
                        hosts=["foo.example.com"], secret_name="tls-secret"
                    )
                ],
            ),
            status=ANY,
        )
        assert ingress.to_dict() == expected.to_dict()

        ingress = await networking_api.read_namespaced_ingress(
            "internal", namespace
        )
        expected = V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=V1ObjectMeta(
                name="internal",
                namespace=namespace,
                annotations={
                    "nginx.ingress.kubernetes.io/auth-method": "GET",
                    "nginx.ingress.kubernetes.io/auth-response-headers": (
                        "X-Auth-Request-Email,X-Auth-Request-User"
                        ",X-Auth-Request-Token"
                    ),
                    "nginx.ingress.kubernetes.io/auth-url": (
                        "https://foo.example.com/auth?scope=read%3Aall"
                        "&scope=read%3Asome&delegate_to=some-service"
                        "&delegate_scope=read%3Aall%2Cread%3Asome"
                    ),
                },
                creation_timestamp=ANY,
                generation=ANY,
                managed_fields=ANY,
                owner_references=[
                    V1OwnerReference(
                        api_version="gafaelfawr.lsst.io/v1alpha1",
                        block_owner_deletion=True,
                        controller=True,
                        kind="GafaelfawrIngress",
                        name="internal-ingress",
                        uid=internal_ingress["metadata"]["uid"],
                    )
                ],
                resource_version=ANY,
                uid=ANY,
            ),
            spec=V1IngressSpec(
                ingress_class_name="nginx",
                rules=[
                    V1IngressRule(
                        host="foo.example.com",
                        http=V1HTTPIngressRuleValue(
                            paths=[
                                V1HTTPIngressPath(
                                    path="/baz",
                                    path_type="ImplementationSpecific",
                                    backend=V1IngressBackend(
                                        service=V1IngressServiceBackend(
                                            name="something",
                                            port=V1ServiceBackendPort(
                                                number=80
                                            ),
                                        )
                                    ),
                                )
                            ]
                        ),
                    )
                ],
            ),
            status=ANY,
        )
        assert ingress.to_dict() == expected.to_dict()


@requires_kubernetes
@pytest.mark.asyncio
async def test_replace(api_client: ApiClient, namespace: str) -> None:
    custom_api = client.CustomObjectsApi(api_client)
    networking_api = client.NetworkingV1Api(api_client)

    with operator_running("gafaelfawr.operator"):
        await custom_api.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            _SMALL_INGRESS,
        )
        await asyncio.sleep(1)

        await networking_api.read_namespaced_ingress("small", namespace)
        small_ingress = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            _SMALL_INGRESS["metadata"]["name"],
        )
        assert small_ingress["status"]["create"] == {
            "lastTransitionTime": ANY,
            "message": "Ingress was created",
            "observedGeneration": small_ingress["metadata"]["generation"],
            "reason": StatusReason.Created.value,
            "status": "True",
            "type": "ResourceCreated",
        }

        await custom_api.patch_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            small_ingress["metadata"]["name"],
            [{"op": "replace", "path": "/config/authType", "value": "basic"}],
        )
        await asyncio.sleep(1)

        ingress = await networking_api.read_namespaced_ingress(
            "small", namespace
        )
        annotations = ingress.metadata.annotations
        assert annotations["nginx.ingress.kubernetes.io/auth-url"] == (
            "https://foo.example.com/auth?scope=read%3Aall&auth_type=basic"
        )
        assert "nginx.ingress.kubernetes.io/auth-signin" not in annotations
        small_ingress = await custom_api.get_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            _SMALL_INGRESS["metadata"]["name"],
        )
        assert small_ingress["status"]["create"] == {
            "lastTransitionTime": ANY,
            "message": "Ingress was updated",
            "observedGeneration": small_ingress["metadata"]["generation"],
            "reason": StatusReason.Updated.value,
            "status": "True",
            "type": "ResourceCreated",
        }

        small_ingress["config"]["loginRedirect"] = True
        await custom_api.replace_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            namespace,
            "gafaelfawringresses",
            small_ingress["metadata"]["name"],
            small_ingress,
        )
        await asyncio.sleep(1)

        ingress = await networking_api.read_namespaced_ingress(
            "small", namespace
        )
        annotations = ingress.metadata.annotations
        assert annotations["nginx.ingress.kubernetes.io/auth-signin"] == (
            "https://foo.example.com/login"
        )
