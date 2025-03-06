"""FastAPI dependencies for checking the return URL.

Several API routes allow the caller to request a redirect back to a return URL
given as a parameter.  To avoid creating an open redirect, those return URLs
must be located at the same hostname as the route being called.  Provide
several variations of a dependency to check this.
"""

from typing import Annotated
from urllib.parse import ParseResult, urlparse

from fastapi import Depends, Header, Query

from ..exceptions import InvalidReturnURLError
from .context import RequestContext, context_dependency

__all__ = [
    "return_url",
    "return_url_with_header",
]


def _check_url(url: str, param: str, context: RequestContext) -> ParseResult:
    """Check that a return URL is at the same host.

    Parameters
    ----------
    url
        The URL to check.
    param
        The name of the query parameter in which the URL was found, for error
        reporting purposes.
    context
        The context of the request.

    Returns
    -------
    ParseResult
        The parsed URL.

    Raises
    ------
    InvalidReturnURLError
        Raised if the return URL was invalid.
    """
    parsed_url = urlparse(url)
    if not context.config.is_hostname_allowed(parsed_url.hostname):
        msg = f"URL is not at {context.config.base_hostname}"
        context.logger.warning("Bad return URL", error=msg)
        raise InvalidReturnURLError(msg, param)

    # Return the parsed URL.
    return parsed_url


async def return_url(
    *,
    rd: Annotated[
        str | None,
        Query(
            title="URL to return to",
            description="User is sent here after operation",
            examples=["https://example.com/"],
        ),
    ] = None,
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> str | None:
    """Validate a return URL in an ``rd`` parameter.

    Returns
    -------
    urllib.parse.ParseResult
        The verified return URL, or `None` if none was given.

    Raises
    ------
    InvalidReturnURLError
        Raised if the return URL was invalid.
    """
    if not rd:
        return None
    context.rebind_logger(return_url=rd)
    _check_url(rd, "rd", context)
    return rd


async def return_url_with_header(
    *,
    rd: Annotated[
        str | None,
        Query(
            title="URL to return to",
            description=(
                "User is sent here after successful authentication. Overrides"
                " `X-Auth-Request-Redirect` if both are set."
            ),
            examples=["https://example.com/"],
        ),
    ] = None,
    x_auth_request_redirect: Annotated[
        str | None,
        Header(
            title="URL to return to",
            description="User is sent here after successful authentication",
            examples=["https://example.com/"],
        ),
    ] = None,
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> str | None:
    """Validate a return URL in an ``rd`` parameter or header.

    Same as `return_url` except also accepts a return URL in the
    ``X-Auth-Request-Redirect`` header if the ``rd`` query parameter was not
    set.

    Returns
    -------
    urllib.parse.ParseResult
        The verified return URL, or `None` if none was given.

    Raises
    ------
    InvalidReturnURLError
        Raised if the return URL was invalid.
    """
    if not rd and x_auth_request_redirect:
        rd = x_auth_request_redirect
    return await return_url(context=context, rd=rd)
