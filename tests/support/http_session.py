"""Mock aiohttp ClientSession for testing."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock

from aiohttp import ClientResponse, ClientSession

if TYPE_CHECKING:
    from typing import Callable, Dict, Optional

    GetCallback = Callable[[Dict[str, str], bool], ClientResponse]
    PostCallback = Callable[
        [Dict[str, str], Dict[str, str], bool], ClientResponse
    ]

__all__ = ["MockClientSession"]


class MockClientSession(Mock):
    """Mock `aiohttp.ClientSession`.

    Intercepts get and post calls and constructs return values based on test
    configuration data.
    """

    def __init__(self) -> None:
        super().__init__(spec=ClientSession)
        self._get_handler: Dict[str, GetCallback] = {}
        self._post_handler: Dict[str, PostCallback] = {}

    def add_get_handler(
        self, url: str, callback: GetCallback, raise_for_status: bool = False
    ) -> None:
        """Set up a handler for a get call.

        Parameters
        ----------
        url : `str`
            The URL to handle.
        callback : `typing.Callable`
            The response to return to this reqeust, called with the headers of
            the request and the raise_for_status argument.
        """
        self._get_handler[url] = callback

    def add_post_handler(
        self, url: str, callback: PostCallback, raise_for_status: bool = False
    ) -> None:
        """Set up a handler for a get call.

        Parameters
        ----------
        url : `str`
            The URL to handle.
        callback : `typing.Callable`
            The response to return to this reqeust, called with the data,
            headers, and raise_for_status argument of the request.
        """
        self._post_handler[url] = callback

    async def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        raise_for_status: bool = False,
    ) -> ClientResponse:
        """Mock retrieving a URL via GET.

        Parameters
        ----------
        url : `str`
            URL to retrieve.
        headers : Dict[`str`, `str`], optional
            Extra headers sent by the client.
        raise_for_status : `bool`, optional
            Whether to raise an exception for a status other than 200.

        Returns
        -------
        response : `aiohttp.ClientResponse`
            The mocked response, which implements status and json().
        """
        if url in self._get_handler:
            if not headers:
                headers = {}
            return self._get_handler[url](headers, raise_for_status)
        else:
            r = Mock(spec=ClientResponse)
            r.status = 404
            return r

    async def post(
        self,
        url: str,
        *,
        data: Dict[str, str],
        headers: Dict[str, str],
        raise_for_status: bool = False,
    ) -> ClientResponse:
        """Mock POST to a URL.

        Parameters
        ----------
        url : `str`
            URL to retrieve.
        data : Dict[`str`, `str`]
            Form data sent in the POST.
        headers : Dict[`str`, `str`]
            Extra headers sent by the client.
        raise_for_status : `bool`, optional
            Whether to raise an exception for a status other than 200.

        Returns
        -------
        response : `aiohttp.ClientResponse`
            The mocked response, which implements status and json().
        """
        if url in self._post_handler:
            return self._post_handler[url](data, headers, raise_for_status)
        else:
            r = Mock(spec=ClientResponse)
            r.status = 404
            return r
