"""Update the request based on ``X-Forwarded-For`` headers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiohttp import web
from aiohttp_remotes.exceptions import RemoteError
from aiohttp_remotes.x_forwarded import XForwardedBase

if TYPE_CHECKING:
    from ipaddress import _BaseNetwork
    from typing import Any, Awaitable, Callable, Dict, Sequence

    Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]

__all__ = ["XForwardedFiltered"]


class XForwardedFiltered(XForwardedBase):
    """Middleware to update the request based on ``X-Forwarded-For``.

    The semantics we want aren't supported by either of the
    :py:mod:`aiohttp_remotes` middleware classes, so we implement our own.
    This is similar to `~aiohttp_remotes.XForwardedRelaxed` except that it
    takes the rightmost IP address that is not contained within one of the
    trusted networks.

    Parameters
    ----------
    trusted : Sequence[Union[`ipaddress.IPv4Network`, `ipaddress.IPv6Network`]]
        List of trusted networks that should be skipped over when finding the
        actual client IP address.
    """

    def __init__(self, trusted: Sequence[_BaseNetwork]):
        self._trusted = trusted

    @web.middleware
    async def middleware(
        self, request: web.Request, handler: Handler
    ) -> web.StreamResponse:
        """Replace request information with details from proxy.

        Honor ``X-Forwarded-For`` and related headers.

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
        try:
            # https://github.com/python/mypy/issues/8772
            overrides: Dict[str, Any] = {}
            headers = request.headers

            forwarded_for = list(reversed(self.get_forwarded_for(headers)))
            if not forwarded_for:
                return await handler(request)

            index = 0
            for ip in forwarded_for:
                if any((ip in network for network in self._trusted)):
                    index += 1
                    continue
                overrides["remote"] = str(ip)
                break

            # If all the IP addresses are from trusted networks, take the
            # left-most.
            if "remote" not in overrides:
                index = -1
                overrides["remote"] = str(forwarded_for[-1])

            # Ideally this should take the scheme corresponding to the entry
            # in X-Forwarded-For that was chosen, but some proxies (the
            # Kubernetes NGINX ingress, for example) only retain one element
            # in X-Forwarded-Proto.  In that case, use what we have.
            proto = list(reversed(self.get_forwarded_proto(headers)))
            if proto:
                if index >= len(proto):
                    index = -1
                overrides["scheme"] = proto[index]

            host = self.get_forwarded_host(headers)
            if host is not None:
                overrides["host"] = host

            request = request.clone(**overrides)
            return await handler(request)

        except RemoteError as exc:
            exc.log(request)
            return await self.raise_error(request)
