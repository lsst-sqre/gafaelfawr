"""FastAPI dependencies for checking the return URL.

Several API routes allow the caller to request a redirect back to a return URL
given as a parameter.  To avoid creating an open redirect, those return URLs
must be located at the same hostname as the route being called.  Provide
several variations of a dependency to check this.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import ParseResult, urlparse

from fastapi import Depends, Header, Query

from ..exceptions import InvalidReturnURLError
from .context import RequestContext, context_dependency

__all__ = ["parsed_redirect_uri", "return_url", "return_url_with_header"]


def _check_url(url: str, param: str, context: RequestContext) -> ParseResult:
    """Check that a return URL is at the same host.

    Parameters
    ----------
    url : `str`
        The URL to check.
    param : `str`
        The name of the query parameter in which the URL was found, for error
        reporting purposes.
    context : `gafaelfawr.dependencies.RequestContext`
        The context of the request.

    Returns
    -------
    parsed_url : `urllib.parse.ParseResult`
        The parsed URL.

    Raises
    ------
    fastapi.HTTPException
        An appropriate error if the return URL was invalid.
    """
    # If X-Forwarded-Host was validated by XForwardedMiddleware, use that
    # instead of the host information from the request URL.
    if context.request.state.forwarded_host:
        hostname = context.request.state.forwarded_host
    else:
        hostname = context.config.realm

    # Check the return URL.
    parsed_url = urlparse(url)
    if parsed_url.hostname != hostname:
        msg = f"URL is not at {hostname}"
        context.logger.warning("Bad return URL", error=msg)
        raise InvalidReturnURLError(msg, param)

    # Return the parsed URL.
    return parsed_url


async def return_url(
    rd: Optional[str] = Query(
        None,
        title="URL to return to",
        description="User is sent here after operation",
        example="https://example.com/",
    ),
    context: RequestContext = Depends(context_dependency),
) -> Optional[str]:
    """Validate a return URL in an ``rd`` parameter.

    Returns
    -------
    return_url : `str` or `None`
        The verified return URL, or `None` if none was given.

    Raises
    ------
    fastapi.HTTPException
        An appropriate error if the return URL was invalid.
    """
    if not rd:
        return None
    context.rebind_logger(return_url=rd)
    _check_url(rd, "rd", context)
    return rd


async def return_url_with_header(
    rd: Optional[str] = Query(
        None,
        title="URL to return to",
        description=(
            "User is sent here after successful authentication. Overrides"
            " X-Auth-Request-Redirect if both are set."
        ),
        example="https://example.com/",
    ),
    x_auth_request_redirect: Optional[str] = Header(
        None,
        title="URL to return to",
        description="User is sent here after successful authentication",
        example="https://example.com/",
    ),
    context: RequestContext = Depends(context_dependency),
) -> Optional[str]:
    """Validate a return URL in an ``rd`` parameter or header.

    Same as :py:func:`return_url` except also accepts a return URL in the
    ``X-Auth-Request-Redirect`` header if the ``rd`` query parameter was not
    set.

    Returns
    -------
    return_url : `str` or `None`
        The verified return URL, or `None` if none was given.

    Raises
    ------
    fastapi.HTTPException
        An appropriate error if the return URL was invalid.
    """
    if not rd and x_auth_request_redirect:
        rd = x_auth_request_redirect
    return await return_url(rd, context)


async def parsed_redirect_uri(
    redirect_uri: str = Query(
        ...,
        title="URL to return to",
        description=(
            "User is sent here after successful or failed authentication"
        ),
        example="https://example.com/",
    ),
    context: RequestContext = Depends(context_dependency),
) -> ParseResult:
    """Validate a return URL in a ``redirect_uri`` parameter.

    Same as :py:func:`return_url` except expects the URL in a ``return_uri``
    parameter instead of ``rd`` and returns a parsed URL instead of the `str`
    form.

    Returns
    -------
    redirect_uri : `urllib.parse.ParseResult`
        The verified, parsed redirect URI.

    Raises
    ------
    fastapi.HTTPException
        An appropriate error if the return URL was invalid.
    """
    context.rebind_logger(return_url=redirect_uri)
    return _check_url(redirect_uri, "redirect_uri", context)
