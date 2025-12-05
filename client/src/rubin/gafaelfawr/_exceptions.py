"""Exceptions for the Gafaelfawr client."""

from __future__ import annotations

from safir.slack.blockkit import SlackException, SlackWebException

__all__ = [
    "GafaelfawrDiscoveryError",
    "GafaelfawrError",
    "GafaelfawrNotFoundError",
    "GafaelfawrValidationError",
    "GafaelfawrWebError",
]


class GafaelfawrError(SlackException):
    """Base class for Gafaelfawr client exceptions."""


class GafaelfawrDiscoveryError(GafaelfawrError):
    """Gafaelfawr was not found in service discovery."""


class GafaelfawrValidationError(GafaelfawrError):
    """Gafaelfawr response did not validate against the expected model."""


class GafaelfawrWebError(SlackWebException, GafaelfawrError):
    """An HTTP request failed."""


class GafaelfawrNotFoundError(GafaelfawrWebError):
    """An HTTP request failed with a 404 response."""
