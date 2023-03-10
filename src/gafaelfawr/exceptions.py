"""Exceptions for Gafaelfawr."""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar, Optional, Self

import kopf
import pydantic
from fastapi import status
from httpx import HTTPError, HTTPStatusError, RequestError
from safir.models import ErrorLocation
from safir.slack.blockkit import (
    SlackCodeAttachment,
    SlackException,
    SlackMessage,
    SlackTextField,
)
from safir.slack.webhook import SlackIgnoredException

__all__ = [
    "DeserializeError",
    "DuplicateTokenNameError",
    "ExternalUserInfoError",
    "FetchKeysError",
    "FirestoreError",
    "FirestoreNotInitializedError",
    "GitHubError",
    "InsufficientScopeError",
    "InvalidClientError",
    "InvalidCSRFError",
    "InvalidCursorError",
    "InvalidExpiresError",
    "InvalidGrantError",
    "InvalidIPAddressError",
    "InvalidMinimumLifetimeError",
    "InvalidRequestError",
    "InvalidReturnURLError",
    "InvalidScopesError",
    "InvalidTokenClaimsError",
    "InvalidTokenError",
    "KubernetesError",
    "KubernetesObjectError",
    "LDAPError",
    "MissingGIDClaimError",
    "MissingUIDClaimError",
    "MissingUsernameClaimError",
    "NoAvailableGidError",
    "NoAvailableUidError",
    "NotConfiguredError",
    "OAuthError",
    "OAuthBearerError",
    "OIDCError",
    "PermissionDeniedError",
    "ProviderError",
    "ProviderWebError",
    "UnauthorizedClientError",
    "UnknownAlgorithmError",
    "UnknownKeyIdError",
    "ValidationError",
    "VerifyTokenError",
]


class ValidationError(SlackIgnoredException, kopf.PermanentError):
    """Represents an input validation error.

    There is a global handler for this exception and all exceptions derived
    from it that returns an HTTP 422 status code with a body that's consistent
    with the error messages generated internally by FastAPI.  It should be
    used for input and parameter validation errors that cannot be caught by
    FastAPI for whatever reason.

    Parameters
    ----------
    message
        The error message (used as the ``msg`` key).
    location
        The part of the request giving rise to the error.
    field
        The field within that part of the request giving rise to the error.

    Notes
    -----
    The FastAPI body format supports returning multiple errors at a time as a
    list in the ``details`` key.  The Gafaelfawr code is not currently capable
    of diagnosing multiple errors at once, so this functionality hasn't been
    implemented.
    """

    error: ClassVar[str] = "validation_failed"
    """Used as the ``type`` field of the error message.

    Should be overridden by any subclass.
    """

    status_code: ClassVar[int] = status.HTTP_422_UNPROCESSABLE_ENTITY
    """HTTP status code for this type of validation error."""

    def __init__(
        self, message: str, location: ErrorLocation, field: str
    ) -> None:
        super().__init__(message)
        self.location = location
        self.field = field

    def to_dict(self) -> dict[str, list[str] | str]:
        """Convert the exception to a dictionary suitable for the exception.

        Returns
        -------
        dict
            Serialized error emssage to pass as the ``detail`` parameter to a
            ``fastapi.HTTPException``.  It is designed to produce the same
            JSON structure as native FastAPI errors.
        """
        return {
            "loc": [self.location.value, self.field],
            "msg": str(self),
            "type": self.error,
        }


class DuplicateTokenNameError(ValidationError):
    """The user tried to reuse the name of a token."""

    error = "duplicate_token_name"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.body, "token_name")


class InvalidCSRFError(ValidationError):
    """Invalid or missing CSRF token."""

    error = "invalid_csrf"
    status_code = status.HTTP_403_FORBIDDEN

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.header, "X-CSRF-Token")


class InvalidCursorError(ValidationError):
    """The provided cursor was invalid."""

    error = "invalid_cursor"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.query, "cursor")


class InvalidDelegateToError(ValidationError):
    """The ``delegate_to`` parameter was set to an invalid value."""

    error = "invalid_delegate_to"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.query, "delegate_to")


class InvalidExpiresError(ValidationError):
    """The provided token expiration time was invalid."""

    error = "invalid_expires"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.body, "expires")


class InvalidIPAddressError(ValidationError):
    """The provided IP address has invalid syntax."""

    error = "invalid_ip_address"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.query, "ip_address")


class InvalidMinimumLifetimeError(ValidationError):
    """The ``minimum_lifetime`` parameter was set to an invalid value."""

    error = "invalid_minimum_lifetime"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.query, "minimum_lifetime")


class InvalidReturnURLError(ValidationError):
    """Client specified an unsafe return URL."""

    error = "invalid_return_url"

    def __init__(self, message: str, field: str) -> None:
        super().__init__(message, ErrorLocation.query, field)


class InvalidScopesError(ValidationError):
    """The provided token scopes are invalid or not available."""

    error = "invalid_scopes"

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorLocation.body, "scopes")


class NotFoundError(ValidationError):
    """The named resource does not exist."""

    error = "not_found"
    status_code = status.HTTP_404_NOT_FOUND


class OAuthError(Exception):
    """An OAuth-related error occurred.

    This class represents both OpenID Connect errors and OAuth 2.0 errors,
    including errors when parsing Authorization headers and bearer tokens.
    """

    error: ClassVar[str] = "invalid_request"
    """The RFC 6749 or RFC 6750 error code for this exception."""

    message: ClassVar[str] = "Unknown error"
    """The summary message to use when logging this error."""

    hide_error: ClassVar[bool] = False
    """Whether to hide the details of the error from the client."""


class InvalidClientError(OAuthError):
    """The provided client_id and client_secret could not be validated.

    This corresponds to the ``invalid_client`` error in RFC 6749: "Client
    authentication failed (e.g., unknown client, no client authentication
    included, or unsupported authentication method)."
    """

    error = "invalid_client"
    message = "Unauthorized client"


class InvalidGrantError(OAuthError):
    """The provided authorization code is not valid.

    This corresponds to the ``invalid_grant`` error in RFC 6749: "The provided
    authorization grant (e.g., authorization code, resource owner credentials)
    or refresh token is invalid, expired, revoked, does not match the
    redirection URI used in the authorization request, or was issued to
    another client."
    """

    error = "invalid_grant"
    message = "Invalid authorization code"
    hide_error = True


class UnsupportedGrantTypeError(OAuthError):
    """The grant type is not supported.

    This corresponds to the ``unsupported_grant_type`` error in RFC 6749: "The
    authorization grant type is not supported by the authorization server."
    """

    error = "unsupported_grant_type"
    message = "Unsupported grant type"


class OAuthBearerError(OAuthError):
    """An error that can be returned as a ``WWW-Authenticate`` challenge.

    Represents the subset of OAuth 2.0 errors defined in RFC 6750 as valid
    errors to return in a ``WWW-Authenticate`` header.  The string form of
    this exception is suitable for use as the ``error_description`` attribute
    of a ``WWW-Authenticate`` header.
    """

    status_code: int = status.HTTP_400_BAD_REQUEST
    """The status code to use for this HTTP error."""


class InvalidRequestError(OAuthBearerError):
    """The provided Authorization header could not be parsed.

    This corresponds to the ``invalid_request`` error in RFC 6749 and 6750:
    "The request is missing a required parameter, includes an unsupported
    parameter or parameter value, repeats the same parameter, uses more than
    one method for including an access token, or is otherwise malformed."
    """

    error = "invalid_request"
    message = "Invalid request"


class InvalidTokenError(OAuthBearerError):
    """The provided token was invalid.

    This corresponds to the ``invalid_token`` error in RFC 6750: "The access
    token provided is expired, revoked, malformed, or invalid for other
    reasons."
    """

    error = "invalid_token"
    message = "Invalid token"
    status_code = status.HTTP_401_UNAUTHORIZED


class InsufficientScopeError(OAuthBearerError):
    """The provided token does not have the right authorization scope.

    This corresponds to the ``insufficient_scope`` error in RFC 6750: "The
    request requires higher privileges than provided by the access token."
    """

    error = "insufficient_scope"
    message = "Permission denied"
    status_code = status.HTTP_403_FORBIDDEN


class DeserializeError(Exception):
    """A stored object could not be decrypted or deserialized.

    Used for data stored in the backing store, such as sessions or user
    tokens.  Should normally be treated the same as a missing object, but
    reported separately so that an error can be logged.
    """


class ExternalUserInfoError(SlackException):
    """Error in external user information source.

    This is the base exception for any error in retrieving information from an
    external source of user data. External sources of data may be affected by
    an external outage, and we don't want to report uncaught exceptions for
    every attempt to query them (possibly multiple times per second), so this
    exception base class is used to catch those errors in the high-traffic
    ``/auth`` route and only log them.
    """


class FirestoreError(ExternalUserInfoError):
    """An error occurred while reading or updating Firestore data."""


class FirestoreNotInitializedError(FirestoreError):
    """Firestore has not been initialized."""


class NoAvailableGidError(FirestoreError):
    """The assigned UID space has been exhausted."""


class NoAvailableUidError(FirestoreError):
    """The assigned UID space has been exhausted."""


class LDAPError(ExternalUserInfoError):
    """User or group information in LDAP was invalid or LDAP calls failed."""


class KubernetesError(Exception):
    """An error occurred during Kubernetes secret processing."""


class KubernetesObjectError(KubernetesError):
    """A Kubernetes object could not be parsed.

    Parameters
    ----------
    kind
        Kind of the malformed Kubernetes object.
    name
        Name of the malformed Kubernetes object.
    namespace
        Namespace of the malformed Kubernetes object.
    exc
        Exception from attempting to parse the object.
    """

    def __init__(
        self,
        kind: str,
        name: str,
        namespace: str,
        exc: pydantic.ValidationError,
    ) -> None:
        msg = f"{kind} {namespace}/{name} is malformed: {str(exc)}"
        super().__init__(msg)


class NotConfiguredError(SlackIgnoredException):
    """The requested operation was not configured."""


class PermissionDeniedError(SlackIgnoredException, kopf.PermanentError):
    """The user does not have permission to perform this operation."""


class ProviderError(SlackException):
    """Something failed while talking to an authentication provider."""


class ProviderWebError(ProviderError):
    """An HTTP request to an authentication provider failed.

    Parameters
    ----------
    message
        Exception string value, which is the default Slack message.
    failed_at
        When the exception happened. Omit to use the current time.
    method
        Method of request.
    url
        URL of the request.
    user
        Username on whose behalf the request is being made.
    status
        Status code of failure, if any.
    reason
        Reason string of failure, if any.
    body
        Body of failure message, if any.
    """

    @classmethod
    def from_exception(
        cls, exc: HTTPError, user: Optional[str] = None
    ) -> Self:
        """Create an exception from an httpx exception.

        Parameters
        ----------
        exc
            Exception from httpx.
        user
            User on whose behalf the request is being made, if known.

        Returns
        -------
        ProviderWebError
            Newly-constructed exception.
        """
        if isinstance(exc, HTTPStatusError):
            status = exc.response.status_code
            method = exc.request.method
            message = f"Status {status} from {method} {exc.request.url}"
            return cls(
                message,
                method=exc.request.method,
                url=str(exc.request.url),
                user=user,
                status=status,
                reason=exc.response.reason_phrase,
                body=exc.response.text,
            )
        else:
            message = f"{type(exc).__name__}: {str(exc)}"
            if isinstance(exc, RequestError):
                return cls(
                    message,
                    method=exc.request.method,
                    url=str(exc.request.url),
                    user=user,
                )
            else:
                return cls(message, user=user)

    def __init__(
        self,
        message: str,
        *,
        failed_at: Optional[datetime] = None,
        method: Optional[str] = None,
        url: Optional[str] = None,
        user: Optional[str] = None,
        status: Optional[int] = None,
        reason: Optional[str] = None,
        body: Optional[str] = None,
    ) -> None:
        self.method = method
        self.url = url
        self.status = status
        self.reason = reason
        self.body = body
        super().__init__(message, user, failed_at=failed_at)

    def to_slack(self) -> SlackMessage:
        """Convert to a Slack message for Slack alerting.

        Returns
        -------
        SlackMessage
            Slack message suitable for posting as an alert.
        """
        message = super().to_slack()
        if self.url:
            message.fields.append(SlackTextField(heading="URL", text=self.url))
        if self.reason:
            field = SlackTextField(heading="Reason", text=self.reason)
            message.fields.append(field)
        if self.body:
            attachment = SlackCodeAttachment(
                heading="Response", code=self.body
            )
            message.attachments.append(attachment)
        return message


class GitHubError(ProviderError):
    """GitHub returned an error from an API call."""


class OIDCError(ProviderError):
    """The OpenID Connect provider returned an error from an API call."""


class OIDCNotEnrolledError(ProviderError):
    """The user is not enrolled in the upstream OpenID Connect provider.

    This is raised when the username claim is missing from the ID token,
    which is how CILogon indicates that no matching enrolled user record
    could be found in LDAP for the federated identity.
    """


class UnauthorizedClientError(Exception):
    """The client is not authorized to request an authorization code.

    This corresponds to the ``unauthorized_client`` error in RFC 6749.
    """


class VerifyTokenError(SlackException):
    """Base exception class for failure in verifying a token."""


class FetchKeysError(ProviderWebError):
    """Cannot retrieve the keys from an issuer."""


class InvalidTokenClaimsError(VerifyTokenError):
    """One of the claims in the token is of an invalid format."""


class MissingGIDClaimError(VerifyTokenError):
    """The token is missing the required GID claim."""


class MissingUIDClaimError(VerifyTokenError):
    """The token is missing the required UID claim."""


class MissingUsernameClaimError(VerifyTokenError):
    """The token is missing the required username claim."""


class UnknownAlgorithmError(VerifyTokenError):
    """The issuer key was for an unsupported algorithm."""


class UnknownKeyIdError(VerifyTokenError):
    """The reqeusted key ID was not found for an issuer."""
