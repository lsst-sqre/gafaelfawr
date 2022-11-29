"""Support functions for Kubernetes operator testing."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import AsyncIterator, Iterator

import pytest
import yaml
from kopf.testing import KopfRunner
from kubernetes_asyncio.client import (
    ApiClient,
    ApiextensionsV1Api,
    CoreV1Api,
    CustomObjectsApi,
    V1Namespace,
    V1ObjectMeta,
)

__all__ = [
    "install_crds",
    "operator_running",
    "requires_kubernetes",
    "run_operator_once",
    "temporary_namespace",
]


requires_kubernetes = pytest.mark.skipif(
    os.getenv("TEST_KUBERNETES") is None,
    reason="Install minikube and set TEST_KUBERNETES to run test",
)
"""Decorator to mark tests that should only be run if Kubernetes is enabled."""


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
    print(runner.stdout)
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
