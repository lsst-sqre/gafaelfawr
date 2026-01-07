"""Exceptions for the Gafaelfawr client."""

from typing import Self, override

from pydantic import ValidationError
from safir.slack.blockkit import (
    SentryEventInfo,
    SlackCodeBlock,
    SlackException,
    SlackMessage,
    SlackWebException,
)

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

    @classmethod
    def from_exception(cls, exc: ValidationError) -> Self:
        """Create an exception from a Pydantic parse failure.

        Parameters
        ----------
        exc
            Pydantic exception.

        Returns
        -------
        GafaelfawrValidationError
            Constructed exception.
        """
        error = f"{type(exc).__name__}: {exc!s}"
        return cls("Unable to parse reply from Gafaelfawr", error)

    def __init__(self, message: str, error: str) -> None:
        super().__init__(message)
        self._message = message
        self.error = error

    @override
    def __str__(self) -> str:
        return f"{self._message}: {self.error}"

    @override
    def to_slack(self) -> SlackMessage:
        message = super().to_slack()
        block = SlackCodeBlock(heading="Validation error", code=self.error)
        message.attachments.append(block)
        return message

    @override
    def to_sentry(self) -> SentryEventInfo:
        info = super().to_sentry()
        info.contexts["validation_info"] = {"error": self.error}
        return info


class GafaelfawrWebError(SlackWebException, GafaelfawrError):
    """An HTTP request failed."""


class GafaelfawrNotFoundError(GafaelfawrWebError):
    """An HTTP request failed with a 404 response."""
