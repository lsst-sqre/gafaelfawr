"""Handler for the GitHub Actions token exchange (``/auth/api/v1/github``).

The exchange endpoint follows the OAuth 2.0 token exchange grammar of RFC
8693 rather than the conventions of the rest of the ``/auth/api/v1`` routes,
since it is consumed by GitHub-hosted tooling rather than by Gafaelfawr's own
clients. It is unauthenticated in Gafaelfawr's usual sense: no Gafaelfawr
token is presented, because the GitHub Actions ID token is the credential.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Response, status
from fastapi.responses import JSONResponse
from safir.models import ErrorModel
from safir.sentry import report_exception
from safir.slack.webhook import SlackRouteErrorHandler

from ..constants import (
    OAUTH_ACCESS_TOKEN_TYPE,
    OAUTH_ID_TOKEN_TYPE,
    OAUTH_TOKEN_EXCHANGE_GRANT_TYPE,
)
from ..dependencies.context import RequestContext, context_dependency
from ..exceptions import (
    FetchKeysError,
    GitHubWebError,
    InvalidRequestError,
    InvalidTokenError,
    OAuthError,
    UnsupportedGrantTypeError,
)
from ..models.github_actions import GitHubTokenExchangeReply
from ..models.oidc import OIDCErrorReply

__all__ = ["router"]

router = APIRouter(
    responses={
        404: {
            "description": "GitHub Actions token exchange not configured",
            "model": ErrorModel,
        },
    },
    route_class=SlackRouteErrorHandler,
)

_UNSUPPORTED_DESCRIPTION = (
    "Not supported by this endpoint and rejected if present, so that a"
    " client cannot believe it has asked for something the endpoint silently"
    " ignored"
)


@router.post(
    "/auth/api/v1/github/token",
    description=(
        "Exchange the OpenID Connect ID token that GitHub issues to a GitHub"
        " Actions job for a Gafaelfawr token, following the OAuth 2.0 token"
        " exchange grammar of"
        " [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693). The ID"
        " token must carry the audience configured for this environment and"
        " satisfy the constraints of an enabled GitHub project, which"
        " determines the bot user, scopes, and lifetime of the minted"
        " token. No Gafaelfawr authentication is required; the ID token is"
        " the credential. Errors use the OAuth 2.0 error document:"
        " `invalid_request` for a malformed request, `unsupported_grant_type`"
        " for a grant type other than token exchange, `invalid_grant` for an"
        " ID token that fails verification or matches no enabled project,"
        " and `invalid_scope` for a requested scope the project does not"
        " allow."
    ),
    response_model=GitHubTokenExchangeReply,
    responses={
        400: {"description": "Request was invalid", "model": OIDCErrorReply},
        502: {
            "description": (
                "GitHub's signing keys could not be retrieved"
                " (`temporarily_unavailable`), so the ID token could not be"
                " verified. Retry the request later."
            ),
            "model": OIDCErrorReply,
        },
    },
    summary="Exchange GitHub Actions ID token",
    tags=["github"],
)
async def post_github_token(
    *,
    grant_type: Annotated[
        str | None,
        Form(
            title="Grant type",
            description=(
                f"Must be `{OAUTH_TOKEN_EXCHANGE_GRANT_TYPE}`, the only"
                " supported grant type"
            ),
            examples=[OAUTH_TOKEN_EXCHANGE_GRANT_TYPE],
        ),
    ] = None,
    subject_token: Annotated[
        str | None,
        Form(
            title="GitHub Actions ID token",
            description=(
                "ID token obtained from GitHub by the workflow job, with the"
                " audience configured for this environment"
            ),
            examples=["eyJhbGciOiJSUzI1NiIsImtpZCI6..."],
        ),
    ] = None,
    subject_token_type: Annotated[
        str | None,
        Form(
            title="Subject token type",
            description=(
                f"Must be `{OAUTH_ID_TOKEN_TYPE}`, the only supported subject"
                " token type"
            ),
            examples=[OAUTH_ID_TOKEN_TYPE],
        ),
    ] = None,
    scope: Annotated[
        str | None,
        Form(
            title="Requested scopes",
            description=(
                "Space-separated scopes for the minted token, which must be"
                " a subset of the scopes of the matching GitHub project. If"
                " omitted or empty, the token receives every scope of the"
                " project."
            ),
            examples=["write:docverse", "exec:linkcheck write:docverse"],
        ),
    ] = None,
    resource: Annotated[
        str | None,
        Form(title="Resource", description=_UNSUPPORTED_DESCRIPTION),
    ] = None,
    audience: Annotated[
        str | None,
        Form(title="Audience", description=_UNSUPPORTED_DESCRIPTION),
    ] = None,
    requested_token_type: Annotated[
        str | None,
        Form(
            title="Requested token type",
            description=(
                _UNSUPPORTED_DESCRIPTION + f". The issued token type is always"
                f" `{OAUTH_ACCESS_TOKEN_TYPE}`"
            ),
        ),
    ] = None,
    actor_token: Annotated[
        str | None,
        Form(title="Actor token", description=_UNSUPPORTED_DESCRIPTION),
    ] = None,
    actor_token_type: Annotated[
        str | None,
        Form(title="Actor token type", description=_UNSUPPORTED_DESCRIPTION),
    ] = None,
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> GitHubTokenExchangeReply | JSONResponse:
    exchange = context.factory.create_github_token_exchange_service()
    try:
        unsupported = {
            "resource": resource,
            "audience": audience,
            "requested_token_type": requested_token_type,
            "actor_token": actor_token,
            "actor_token_type": actor_token_type,
        }
        token, scopes = _parse_request(
            grant_type=grant_type,
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            scope=scope,
            unsupported=unsupported,
        )
        result = await exchange.exchange_token(
            token, scopes=scopes, ip_address=context.ip_address
        )
    except InvalidTokenError:
        # The exchange raises this only if the minted token could not be
        # stored. That is a server fault rather than a problem with the
        # request, so let it propagate as an uncaught exception, which
        # reports it to Slack and Sentry and returns a 500 error, rather
        # than mapping it to a 400 error below.
        raise
    except OAuthError as e:
        context.logger.warning(e.message, error=str(e))
        content = {
            "error": e.error,
            "error_description": e.message if e.hide_error else str(e),
        }
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST, content=content
        )
    except (FetchKeysError, GitHubWebError) as e:
        # Verifying the ID token needs GitHub's signing keys, and GitHub may
        # be down. That is not the caller's fault and they should retry, so
        # report it to Slack and Sentry and return a Bad Gateway error in
        # the OAuth 2.0 error document format rather than letting it
        # propagate as an uncaught exception.
        msg = "Unable to retrieve GitHub Actions signing keys, retry later"
        context.logger.exception(msg, error=str(e))
        slack_client = context.factory.create_slack_client()
        await report_exception(e, slack_client=slack_client)
        content = {
            "error": "temporarily_unavailable",
            "error_description": msg,
        }
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY, content=content
        )

    # Record the exchange as a metrics event, so that a token can be traced
    # to the exact workflow run that obtained it. The token has already been
    # minted, so a failure to publish the event must not fail the exchange:
    # the workflow would retry and mint a second live token. Report the
    # failure instead, since the exchange is still recorded in the token
    # change history and the logs.
    try:
        event = exchange.build_event(result)
        await context.events.github_token_exchange.publish(event)
    except Exception as e:
        msg = "Unable to publish GitHub token exchange event"
        context.logger.exception(msg, token_key=result.token.key, error=str(e))
        slack_client = context.factory.create_slack_client()
        await report_exception(e, slack_client=slack_client)

    # Return the token to the caller. The headers are mandated by RFC 6749.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return result.to_reply()


def _parse_request(
    *,
    grant_type: str | None,
    subject_token: str | None,
    subject_token_type: str | None,
    scope: str | None,
    unsupported: dict[str, str | None],
) -> tuple[str, set[str] | None]:
    """Check the grammar of a token exchange request.

    Parameters
    ----------
    grant_type
        Grant type of the request.
    subject_token
        Subject token of the request.
    subject_token_type
        Type of the subject token.
    scope
        Requested scopes as a space-separated list, if any.
    unsupported
        Parameters that the endpoint does not support, by name, with their
        values if present.

    Returns
    -------
    tuple
        The subject token and the requested scopes, or `None` for the
        latter if no scope was requested.

    Raises
    ------
    InvalidRequestError
        Raised if a required parameter is missing, the subject token type is
        not supported, the scope is empty, or an unsupported parameter is
        present.
    UnsupportedGrantTypeError
        Raised if the grant type is not token exchange.
    """
    if not grant_type:
        raise InvalidRequestError("Missing grant_type parameter")
    if grant_type != OAUTH_TOKEN_EXCHANGE_GRANT_TYPE:
        msg = (
            f"Unsupported grant type {grant_type}, must be"
            f" {OAUTH_TOKEN_EXCHANGE_GRANT_TYPE}"
        )
        raise UnsupportedGrantTypeError(msg)
    if not subject_token_type:
        raise InvalidRequestError("Missing subject_token_type parameter")
    if subject_token_type != OAUTH_ID_TOKEN_TYPE:
        msg = (
            f"Unsupported subject token type {subject_token_type}, must be"
            f" {OAUTH_ID_TOKEN_TYPE}"
        )
        raise InvalidRequestError(msg)
    if not subject_token:
        raise InvalidRequestError("Missing subject_token parameter")
    present = sorted(k for k, v in unsupported.items() if v is not None)
    if present:
        msg = f"Unsupported parameters: {', '.join(present)}"
        raise InvalidRequestError(msg)
    if scope is None:
        return subject_token, None
    scopes = set(scope.split())
    if not scopes:
        raise InvalidRequestError("Empty scope parameter")
    return subject_token, scopes
