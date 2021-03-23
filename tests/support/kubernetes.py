"""Mock Kubernetes API for testing."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock

import kubernetes
from kubernetes.client import ApiException, V1Secret, V1SecretList

if TYPE_CHECKING:
    from typing import Any, Callable, Dict, List, Optional

__all__ = ["MockCoreV1Api", "assert_kubernetes_objects_are"]


def assert_kubernetes_objects_are(
    mock_kubernetes: MockCoreV1Api, expected: List[Any]
) -> None:
    """Assert that Kubernetes contains only the specified models."""
    seen = mock_kubernetes.get_all_objects_for_test()
    expected_sorted = sorted(
        expected, key=lambda o: (o.metadata.namespace, o.metadata.name)
    )
    assert seen == expected_sorted


class MockCoreV1Api(Mock):
    """Mock Kubernetes API for testing.

    This object simulates (with almost everything left out) the
    `kubernetes.client.CoreV1Api` client object while keeping simple internal
    state.  It is intended to be used as a mock inside tests.

    Methods ending with ``_for_test`` are outside of the API and are intended
    for use by the test suite.  All other methods mock corresonding methods of
    `kubernetes.client.CoreV1Api`.
    """

    error_callback: Optional[Callable[..., None]] = None
    """Called before each method if set."""

    objects: Dict[str, Dict[str, object]] = {}
    """All objects stored in Kubernetes."""

    @classmethod
    def reset_for_test(cls) -> None:
        """Must be called before each test run."""
        cls.objects = {}
        cls.error_callback = None

    def __init__(self) -> None:
        super().__init__(spec=kubernetes.client.CoreV1Api)

    def get_all_objects_for_test(self) -> List[object]:
        """Return all objects sorted by namespace and name."""
        results = []
        for namespace in sorted(self.objects.keys()):
            for name in sorted(self.objects[namespace].keys()):
                results.append(self.objects[namespace][name])
        return results

    @staticmethod
    def _maybe_error(method: str, *args: Any) -> None:
        """Helper function to avoid using class method call syntax."""
        if MockCoreV1Api.error_callback:
            callback = MockCoreV1Api.error_callback
            callback(method, *args)

    # SECRETS API

    def create_namespaced_secret(
        self, namespace: str, secret: V1Secret
    ) -> None:
        self._maybe_error("create_namespaced_secret", namespace, secret)
        assert namespace == secret.metadata.namespace
        name = secret.metadata.name
        if namespace not in self.objects:
            self.objects[namespace] = {}
        if name in self.objects[namespace]:
            raise ApiException(status=500, reason=f"{namespace}/{name} exists")
        self.objects[namespace][name] = secret

    def delete_namespaced_secret(self, name: str, namespace: str) -> None:
        self._maybe_error("delete_namespaced_secret", name, namespace)
        self.read_namespaced_secret(name, namespace)
        del self.objects[namespace][name]

    def list_secret_for_all_namespaces(
        self, label_selector: str
    ) -> V1SecretList:
        """Only supports a simple equality label selector."""
        self._maybe_error("list_secret_for_all_namespaces", label_selector)
        label, value = label_selector.split("=")
        results = []
        for namespace in self.objects.keys():
            for obj in self.objects[namespace].values():
                if not isinstance(obj, V1Secret):
                    continue
                if not obj.metadata.labels:
                    continue
                if label not in obj.metadata.labels:
                    continue
                if obj.metadata.labels[label] == value:
                    results.append(obj)
        return V1SecretList(items=results)

    def patch_namespaced_secret(
        self,
        name: str,
        namespace: str,
        patch: List[Dict[str, str]],
    ) -> None:
        self._maybe_error("patch_namespaced_secret", name, namespace, patch)
        assert len(patch) == 1, "Multiple patches not supported"
        change = patch[0]
        assert change["op"] == "replace"
        assert change["path"].startswith("/data/")
        key = change["path"][len("/data/") :]
        secret = self.read_namespaced_secret(name, namespace)
        secret.data[key] = change["value"]
        print("Updating", key, change["value"])

    def read_namespaced_secret(self, name: str, namespace: str) -> V1Secret:
        self._maybe_error("read_namespaced_secret", name, namespace)
        if namespace not in self.objects:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        if name not in self.objects[namespace]:
            reason = f"{namespace}/{name} not found"
            raise ApiException(status=404, reason=reason)
        assert isinstance(
            self.objects[namespace][name], V1Secret
        ), "Name conflicts between objects not supported"
        return self.objects[namespace][name]
