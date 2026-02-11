"""Client for Gafaelfawr."""

try:
    import pytest

    pytest.register_assert_rewrite("rubin.gafaelfawr.client._mock")
except ImportError:
    pass

from ._client import GafaelfawrClient
from ._dependencies import GafaelfawrDependency, gafaelfawr_dependency
from ._exceptions import (
    GafaelfawrDiscoveryError,
    GafaelfawrError,
    GafaelfawrNotFoundError,
    GafaelfawrValidationError,
    GafaelfawrWebError,
)
from ._mock import (
    MockGafaelfawr,
    MockGafaelfawrAction,
    register_mock_gafaelfawr,
)
from ._models import (
    GafaelfawrGroup,
    GafaelfawrNotebookQuota,
    GafaelfawrQuota,
    GafaelfawrTapQuota,
    GafaelfawrUserInfo,
)
from ._tokens import create_token

__all__ = [
    "GafaelfawrClient",
    "GafaelfawrDependency",
    "GafaelfawrDiscoveryError",
    "GafaelfawrError",
    "GafaelfawrGroup",
    "GafaelfawrNotFoundError",
    "GafaelfawrNotebookQuota",
    "GafaelfawrQuota",
    "GafaelfawrTapQuota",
    "GafaelfawrUserInfo",
    "GafaelfawrValidationError",
    "GafaelfawrWebError",
    "MockGafaelfawr",
    "MockGafaelfawrAction",
    "create_token",
    "gafaelfawr_dependency",
    "register_mock_gafaelfawr",
]
