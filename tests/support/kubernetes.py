"""Support functions for Kubernetes operator testing."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterable, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import ANY

import pytest
import yaml
from kopf.testing import KopfRunner
from kubernetes_asyncio.client import (
    ApiClient,
    ApiextensionsV1Api,
    CoreV1Api,
    CustomObjectsApi,
    NetworkingV1Api,
    V1Namespace,
    V1ObjectMeta,
)
from safir.datetime import current_datetime

from gafaelfawr.constants import NGINX_SNIPPET
from gafaelfawr.models.kubernetes import KubernetesResourceStatus, StatusReason

__all__ = [
    "assert_resources_match",
    "create_custom_resources",
    "install_crds",
    "operator_running",
    "requires_kubernetes",
    "run_operator_once",
    "temporary_namespace",
]

_PLURALS = {
    "GafaelfawrIngress": "gafaelfawringresses",
    "GafaelfawrServiceToken": "gafaelfawrservicetokens",
}
"""Mapping of kinds to plurals for the custom object API."""


requires_kubernetes = pytest.mark.skipif(
    os.getenv("TEST_KUBERNETES") is None,
    reason="Install minikube and set TEST_KUBERNETES to run test",
)
"""Decorator to mark tests that should only be run if Kubernetes is enabled."""


def _replace_any(data: Any) -> Any:
    """Replace ``<ANY>`` strings with `~unittest.mock.ANY`."""
    if isinstance(data, str):
        return ANY if data == "<ANY>" else data
    elif isinstance(data, Mapping):
        return {k: _replace_any(v) for k, v in data.items()}
    elif isinstance(data, Iterable):
        return [_replace_any(e) for e in data]
    else:
        return data


def operator_test_input(filename: str, namespace: str) -> list[dict[str, Any]]:
    """Read input for a Kubernetes operator test from a file.

    Parameters
    ----------
    filename
        Name of file in ``tests/data/kubernetes/input`` containing the
        resources in YAML format.
    namespace
        Namespace to use for the objects.

    Returns
    -------
    list of dict
        The custom resources.
    """
    path = (
        Path(__file__).parent.parent
        / "data"
        / "kubernetes"
        / "input"
        / (filename + ".yaml")
    )
    resources = path.read_text().format(namespace=namespace, braces="{}")
    return list(yaml.safe_load_all(resources))


def operator_test_output(
    filename: str, namespace: str
) -> list[dict[str, Any]]:
    """Read output for a Kubernetes operator test from a file.

    Parameters
    ----------
    filename
        Name of file in ``tests/data/kubernetes/output`` containing the
        resources in YAML format.
    namespace
        Namespace to use for the objects.

    Returns
    -------
    list of dict
        The custom resources.
    """
    path = (
        Path(__file__).parent.parent
        / "data"
        / "kubernetes"
        / "output"
        / (filename + ".yaml")
    )
    snippet = NGINX_SNIPPET.replace("\n", "\n      ").rstrip(" ")
    resources = path.read_text().format(
        namespace=namespace, braces="{}", any="<ANY>", snippet=snippet
    )
    return _replace_any(yaml.safe_load_all(resources))


async def create_custom_resources(
    api_client: ApiClient, resources: list[dict[str, Any]]
) -> None:
    """Create test resources.

    Parameters
    ----------
    api_client
        Kubernetes client.
    resources
        The resources to create.
    """
    custom_api = CustomObjectsApi(api_client)
    for resource in resources:
        await custom_api.create_namespaced_custom_object(
            "gafaelfawr.lsst.io",
            "v1alpha1",
            resource["metadata"]["namespace"],
            _PLURALS[resource["kind"]],
            resource,
        )


async def assert_custom_resource_status_is(
    api_client: ApiClient,
    resource: dict[str, Any],
    status: KubernetesResourceStatus,
) -> None:
    """Assert that the status of a custom object matches.

    Parameters
    ----------
    api_client
        Kubernetes client.
    resource
        The custom resource to check. It will be retrieved from Kubernetes
        again to get its updated status.
    status
        The expected status.
    """
    custom_api = CustomObjectsApi(api_client)
    seen = await custom_api.get_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        resource["metadata"]["namespace"],
        _PLURALS[resource["kind"]],
        resource["metadata"]["name"],
    )
    status_value = "False" if status.reason == StatusReason.Failed else "True"
    assert seen["status"] == {
        "create": {
            "lastTransitionTime": ANY,
            "message": status.message,
            "observedGeneration": seen["metadata"]["generation"],
            "reason": status.reason.value,
            "status": status_value,
            "type": "ResourceCreated",
        }
    }
    transition_str = seen["status"]["create"]["lastTransitionTime"]
    assert transition_str.endswith("Z")
    transition = datetime.fromisoformat(transition_str)
    now = current_datetime()
    assert now - timedelta(seconds=30) <= transition <= now


async def assert_resources_match(
    api_client: ApiClient, resources: list[dict[str, Any]]
) -> None:
    """Assert that output resources match the provided file match.

    Also verifies there are no output resources of the indicated type in the
    given namespace, except possibly for ones starting with ``default`` (to
    allow for the ``Secret`` resources holding tokens for the default service
    account).

    Parameters
    ----------
    api_client
        Kubernetes client.
    resources
        The resources to compare. All resources must have the same ``kind``.
    """
    kind = resources[0]["kind"]

    checked = set()
    for expected in resources:
        name = expected["metadata"]["name"]
        namespace = expected["metadata"]["namespace"]
        if kind == "Secret":
            core_api = CoreV1Api(api_client)
            seen = await core_api.read_namespaced_secret(name, namespace)
        elif kind == "Ingress":
            net_api = NetworkingV1Api(api_client)
            seen = await net_api.read_namespaced_ingress(name, namespace)
        else:
            pytest.fail(f"Unknown object kind {kind}")
        assert api_client.sanitize_for_serialization(seen) == expected
        checked.add(name)

    if kind == "Secret":
        core_api = CoreV1Api(api_client)
        secrets = await core_api.list_namespaced_secret(namespace)
        for secret in secrets.items:
            name = secret.metadata.name
            assert name in checked, f"Unexpected secret {name}"
    elif kind == "Ingress":
        net_api = NetworkingV1Api(api_client)
        ingresses = await net_api.list_namespaced_ingress(namespace)
        for ingress in ingresses.items:
            name = ingress.metadata.name
            assert name in checked, f"Unexpected ingress {name}"
    else:
        pytest.fail(f"Unknown object kind {kind}")


async def install_crds(api_client: ApiClient) -> None:
    """Install the test CRDs in the default Kubernetes cluster.

    Parameters
    ----------
    api_client
        Kubernetes API client to use.
    """
    extensions_api = ApiextensionsV1Api(api_client)
    crds_path = Path(__file__).parent.parent.parent / "crds"
    for crd in crds_path.iterdir():
        if crd.suffix != ".yaml":
            continue
        with crd.open("r") as fh:
            crd_data = yaml.safe_load(fh)
        await extensions_api.create_custom_resource_definition(crd_data)


@contextmanager
def operator_running(module: str) -> Iterator[None]:
    """Start the Kopf operator as a context manager.

    This is a wrapper around `kopf.testing.KopfRunner` that constructs an
    appropriate command line and verifies that the operator didn't fail.

    Parameters
    ----------
    module
        Name of the module that provides the operator.
    """
    kopf_command = [
        "run",
        "-A",
        "--verbose",
        "--log-format=json",
        "-m",
        module,
    ]
    with KopfRunner(kopf_command) as runner:
        yield
    assert runner.exit_code == 0
    assert runner.exception is None


async def run_operator_once(module: str, *, delay: float = 1) -> None:
    """Run the Kopf operator, wait for a delay, and then shut it down.

    This does a single run of the operator, processing any pending changes,
    and then shuts it down again.

    Parameters
    ----------
    module
        Name of the module that provides the operator.
    delay
        How long to wait after the operator has started before shutting it
        down again.
    """
    with operator_running(module):
        await asyncio.sleep(delay)


@asynccontextmanager
async def temporary_namespace(api_client: ApiClient) -> AsyncIterator[str]:
    """Create a temporary namespace for testing.

    Each test uses a separate namespace, since Kubernetes can be very slow to
    delete namespaces.  Try to remove the finalizers on any custom objects in
    the namespace before deleting it so that Kubernetes will actually clean
    up.

    Parameters
    ----------
    api_client
        Kubernetes API client to use.
    """
    core_api = CoreV1Api(api_client)
    custom_api = CustomObjectsApi(api_client)
    namespace = f"test-{os.urandom(8).hex()}"
    await core_api.create_namespace(
        V1Namespace(
            api_version="v1",
            kind="Namespace",
            metadata=V1ObjectMeta(name=namespace),
        )
    )

    yield namespace

    # Remove finalizers from all of our custom objects so that they can be
    # deleted without Kopf running.
    ingresses = await custom_api.list_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        namespace,
        "gafaelfawringresses",
    )
    for ingress in ingresses["items"]:
        if "finalizers" in ingress["metadata"]:
            await custom_api.patch_namespaced_custom_object(
                "gafaelfawr.lsst.io",
                "v1alpha1",
                namespace,
                "gafaelfawringresses",
                ingress["metadata"]["name"],
                [{"op": "remove", "path": "/metadata/finalizers"}],
            )
    service_tokens = await custom_api.list_namespaced_custom_object(
        "gafaelfawr.lsst.io",
        "v1alpha1",
        namespace,
        "gafaelfawrservicetokens",
    )
    for service_token in service_tokens["items"]:
        if "finalizers" in service_token["metadata"]:
            await custom_api.patch_namespaced_custom_object(
                "gafaelfawr.lsst.io",
                "v1alpha1",
                namespace,
                "gafaelfawrservicetokens",
                service_token["metadata"]["name"],
                [{"op": "remove", "path": "/metadata/finalizers"}],
            )

    await core_api.delete_namespace(namespace)
