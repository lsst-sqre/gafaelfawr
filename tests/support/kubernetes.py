"""Mock Kubernetes API for testing."""

from __future__ import annotations

import copy
import os
import uuid
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock, patch

import kubernetes_asyncio
from kubernetes_asyncio.client import ApiClient, ApiException, V1Secret

if TYPE_CHECKING:
    from typing import Any, Callable, Dict, Iterator, List, Optional

__all__ = [
    "MockKubernetesApi",
    "assert_kubernetes_objects_are",
    "patch_kubernetes",
]


def assert_kubernetes_objects_are(
    mock_kubernetes: MockKubernetesApi, kind: str, expected: List[Any]
) -> None:
    """Assert that Kubernetes contains only the specified models."""
    seen = mock_kubernetes.get_all_objects_for_test(kind)
    expected_sorted = sorted(
        expected, key=lambda o: (o.metadata.namespace, o.kind, o.metadata.name)
    )
    assert seen == expected_sorted


class MockKubernetesApi(Mock):
    """Mock Kubernetes API for testing.

    This object simulates (with almost everything left out) the ``CoreV1Api``
    and ``CustomObjectApi`` client objects while keeping simple internal
    state.  It is intended to be used as a mock inside tests.

    Methods ending with ``_for_test`` are outside of the API and are intended
    for use by the test suite.
    """

    def __init__(self) -> None:
        super().__init__(spec=kubernetes_asyncio.client.CoreV1Api)
        self.error_callback: Optional[Callable[..., None]] = None
        self.objects: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def get_all_objects_for_test(self, kind: str) -> List[Any]:
        """Return all objects of a given kind sorted by namespace and name."""
        results = []
        for namespace in sorted(self.objects.keys()):
            if kind not in self.objects[namespace]:
                continue
            for name in sorted(self.objects[namespace][kind].keys()):
                results.append(self.objects[namespace][kind][name])
        return results

    def _maybe_error(self, method: str, *args: Any) -> None:
        """Helper function to avoid using class method call syntax."""
        if self.error_callback:
            callback = self.error_callback
            callback(method, *args)

    # CUSTOM OBJECT API

    async def create_namespaced_custom_object(
        self,
        group: str,
        version: str,
        namespace: str,
        plural: str,
        body: Dict[str, Any],
    ) -> None:
        self._maybe_error(
            "create_namespaced_custom_object",
            group,
            version,
            namespace,
            plural,
            body,
        )
        assert group == "gafaelfawr.lsst.io"
        assert version == "v1alpha1"
        assert plural == "gafaelfawrservicetokens"
        assert body["kind"] == "GafaelfawrServiceToken"
        assert namespace == body["metadata"]["namespace"]
        name = body["metadata"]["name"]
        obj = copy.deepcopy(body)
        obj["metadata"]["uid"] = str(uuid.uuid4())
        if namespace not in self.objects:
            self.objects[namespace] = {}
        if body["kind"] not in self.objects[namespace]:
            self.objects[namespace][body["kind"]] = {}
        if name in self.objects[namespace][body["kind"]]:
            raise ApiException(status=500, reason=f"{namespace}/{name} exists")
        self.objects[namespace][body["kind"]][name] = obj

    async def get_namespaced_custom_object(
        self,
        group: str,
        version: str,
        namespace: str,
        plural: str,
        name: str,
    ) -> Dict[str, Any]:
        assert group == "gafaelfawr.lsst.io"
        assert version == "v1alpha1"
        assert plural == "gafaelfawrservicetokens"
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        kind = "GafaelfawrServiceToken"
        if name not in self.objects[namespace].get(kind, {}):
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        return self.objects[namespace][kind][name]

    async def list_cluster_custom_object(
        self, group: str, version: str, plural: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        self._maybe_error("list_cluster_custom_object", group, version, plural)
        assert group == "gafaelfawr.lsst.io"
        assert version == "v1alpha1"
        if plural == "gafaelfawrservicetokens":
            kind = "GafaelfawrServiceToken"
        else:
            assert False, f"unknown object plural {plural}"
        results = []
        for namespace in self.objects.keys():
            for name in self.objects[namespace][kind].keys():
                results.append(self.objects[namespace][kind][name])
        return {"items": results}

    async def patch_namespaced_custom_object_status(
        self,
        group: str,
        version: str,
        namespace: str,
        plural: str,
        name: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        assert group == "gafaelfawr.lsst.io"
        assert version == "v1alpha1"
        assert plural == "gafaelfawrservicetokens"
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        kind = "GafaelfawrServiceToken"
        if name not in self.objects[namespace].get(kind, {}):
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        assert "status" in body
        assert "conditions" in body["status"]
        obj = copy.deepcopy(self.objects[namespace][kind][name])
        if "status" not in obj:
            obj["status"] = {}
        obj["status"]["conditions"] = body["status"]["conditions"]
        self.objects[namespace][kind][name] = obj
        return obj

    async def replace_namespaced_custom_object(
        self,
        group: str,
        version: str,
        namespace: str,
        plural: str,
        name: str,
        body: Dict[str, Any],
    ) -> None:
        self._maybe_error(
            "replace_namespaced_custom_object",
            group,
            version,
            namespace,
            plural,
            name,
            body,
        )
        assert group == "gafaelfawr.lsst.io"
        assert version == "v1alpha1"
        assert plural == "gafaelfawrservicetokens"
        assert body["kind"] == "GafaelfawrServiceToken"
        assert namespace == body["metadata"]["namespace"]
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        if name not in self.objects[namespace].get(body["kind"], {}):
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        self.objects[namespace][body["kind"]][name] = body

    # SECRETS API

    async def create_namespaced_secret(
        self, namespace: str, secret: V1Secret
    ) -> None:
        self._maybe_error("create_namespaced_secret", namespace, secret)
        assert namespace == secret.metadata.namespace
        name = secret.metadata.name
        if namespace not in self.objects:
            self.objects[namespace] = {}
        if "Secret" not in self.objects[namespace]:
            self.objects[namespace]["Secret"] = {}
        if name in self.objects[namespace]["Secret"]:
            raise ApiException(status=500, reason=f"{namespace}/{name} exists")
        self.objects[namespace]["Secret"][name] = secret

    async def patch_namespaced_secret(
        self, name: str, namespace: str, body: List[Dict[str, Any]]
    ) -> V1Secret:
        self._maybe_error("patch_namespaced_secret", name, namespace)
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        if name not in self.objects[namespace].get("Secret", {}):
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        obj = copy.deepcopy(self.objects[namespace]["Secret"][name])
        for change in body:
            assert change["op"] == "replace"
            if change["path"] == "/metadata/annotations":
                obj.metadata.annotations = change["value"]
            elif change["path"] == "/metadata/labels":
                obj.metadata.labels = change["value"]
            else:
                assert False, f'unsupported path {change["path"]}'
        self.objects[namespace]["Secret"][name] = obj

    async def read_namespaced_secret(
        self, name: str, namespace: str
    ) -> V1Secret:
        self._maybe_error("read_namespaced_secret", name, namespace)
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        if name not in self.objects[namespace].get("Secret", {}):
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        return self.objects[namespace]["Secret"][name]

    async def replace_namespaced_secret(
        self, name: str, namespace: str, secret: V1Secret
    ) -> None:
        self._maybe_error("replace_namespaced_secret", namespace, secret)
        name = secret.metadata.name
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        if name not in self.objects[namespace].get("Secret", {}):
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        self.objects[namespace]["Secret"][name] = secret


def patch_kubernetes() -> Iterator[MockKubernetesApi]:
    """Replace the Kubernetes API with a mock class.

    Returns
    -------
    mock_kubernetes : `tests.support.kubernetes.MockKubernetesApi`
        The mock Kubernetes API object.
    """
    with patch.object(kubernetes_asyncio.config, "load_incluster_config"):
        mock_api = MockKubernetesApi()
        patchers = []
        for api in ("CoreV1Api", "CustomObjectsApi"):
            patcher = patch.object(kubernetes_asyncio.client, api)
            mock_class = patcher.start()
            mock_class.return_value = mock_api
            patchers.append(patcher)
        with patch.object(kubernetes_asyncio.client, "ApiClient") as client:
            client.return_value = MagicMock(spec=ApiClient)
            os.environ["KUBERNETES_PORT"] = "tcp://10.0.0.1:443"
            yield mock_api
            del os.environ["KUBERNETES_PORT"]
        for patcher in patchers:
            patcher.stop()
