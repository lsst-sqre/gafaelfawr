"""Client for Gafaelfawr."""

from ._client import GafaelfawrClient
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
    GafaelfawrTokenData,
    GafaelfawrUserInfo,
)

__all__ = [
    "GafaelfawrClient",
    "GafaelfawrDiscoveryError",
    "GafaelfawrError",
    "GafaelfawrGroup",
    "GafaelfawrNotFoundError",
    "GafaelfawrNotebookQuota",
    "GafaelfawrQuota",
    "GafaelfawrTapQuota",
    "GafaelfawrTokenData",
    "GafaelfawrUserInfo",
    "GafaelfawrValidationError",
    "GafaelfawrWebError",
    "MockGafaelfawr",
    "MockGafaelfawrAction",
    "register_mock_gafaelfawr",
]
