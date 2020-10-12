"""Update the request based on ``X-Forwarded-For`` headers."""

from __future__ import annotations

from ipaddress import ip_address
from typing import TYPE_CHECKING

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from gafaelfawr.fastapi.dependencies import config

if TYPE_CHECKING:
    from ipaddress import _BaseAddress
    from typing import Awaitable, Callable, List

__all__ = ["XForwardedMiddleware"]


class XForwardedMiddleware(BaseHTTPMiddleware):
    """Middleware to update the request based on ``X-Forwarded-For``."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Middleware to update the request based on ``X-Forwarded-For``.

        Parameters
        ----------
        request : `aiohttp.web.Request`
            The aiohttp.web request.
        handler : `typing.Callable`
            The application's request handler.

        Returns
        -------
        response : `aiohttp.web.StreamResponse`
            The response with a new ``logger`` key attached to it.

        Notes
        -----
        The remote IP address will be replaced with the right-most IP address
        in ``X-Forwarded-For`` that is not contained within one of the trusted
        networks.  The last entry of ``X-Forwarded-Proto`` and the contents of
        ``X-Forwarded-Host`` will be used unconditionally if they are present
        and ``X-Forwarded-For`` is also present.
        """
        forwarded_for = list(reversed(self._get_forwarded_for(request)))
        if not forwarded_for:
            return await call_next(request)

        client = None
        for ip in forwarded_for:
            if any((ip in network for network in config().proxies)):
                continue
            client = str(ip)
            break

        # If all the IP addresses are from trusted networks, take the
        # left-most.
        if not client:
            client = str(forwarded_for[-1])

        request.scope["client"] = (client, request.client.port)

        return await call_next(request)

    def _get_forwarded_for(self, request: Request) -> List[_BaseAddress]:
        forwarded_for_str = request.headers.getlist("X-Forwarded-For")
        if not forwarded_for_str or len(forwarded_for_str) > 1:
            return []
        forwarded_for = [
            ip_address(addr)
            for addr in (a.strip() for a in forwarded_for_str[0].split(","))
            if addr
        ]
        return forwarded_for
