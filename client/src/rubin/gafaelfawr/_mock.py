"""Mock for the parts of the Gafaelfawr API used by the client."""

from __future__ import annotations

import base64
import os
import re
from collections import defaultdict
from collections.abc import Callable, Iterable
from enum import Enum
from functools import wraps
from typing import Concatenate
from urllib.parse import urljoin

import respx
from httpx import Request, Response
from rubin.repertoire import DiscoveryClient

from ._models import GafaelfawrTokenData, GafaelfawrUserInfo

__all__ = [
    "MockGafaelfawr",
    "MockGafaelfawrAction",
    "register_mock_gafaelfawr",
]


class MockGafaelfawrAction(Enum):
    """Possible actions that could fail."""

    USER_INFO = "user_info"


class MockGafaelfawr:
    """Mock for the parts of the Gafaelfawr API used by the client."""

    def __init__(self) -> None:
        self._fail: defaultdict[str, set[MockGafaelfawrAction]]
        self._fail = defaultdict(set)
        self._tokens: dict[str, GafaelfawrTokenData] = {}
        self._user_info: dict[str, GafaelfawrUserInfo | None] = {}

    def create_token(
        self, username: str, *, scopes: Iterable[str] | None = None
    ) -> str:
        """Create a token for the given username.

        This token will only be recognized by the same instance of the
        Gafaelfawr mock.

        Parameters
        ----------
        username
            Username the token is for.
        scopes
            If provided, list of scopes to assign to the token. This is
            primarily needed if the client will call a privileged API
            endpoint.

        Returns
        -------
        str
            New Gafaelfawr token.
        """
        key = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
        secret = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
        token = f"gt-{key}-{secret}"
        self._tokens[token] = GafaelfawrTokenData(
            token=token,
            username=username,
            scopes=set(scopes) if scopes else set(),
        )
        return token

    def fail_on(
        self,
        username: str,
        actions: MockGafaelfawrAction | Iterable[MockGafaelfawrAction],
    ) -> None:
        """Configure the API to fail on requests for the given user.

        This can be used by test suites to test handling of Gafaelfawr
        failures.

        Parameters
        ----------
        username
            Username for which operations should fail.
        actions
            An action or iterable of actions that should fail. Pass in the
            empty list to restore regular operations for this user.
        """
        if isinstance(actions, MockGafaelfawrAction):
            self._fail[username] = {actions}
        else:
            self._fail[username] = set(actions)

    def install_routes(self, respx_mock: respx.Router, base_url: str) -> None:
        """Install the mock routes for the Gafaelfawr API.

        Parameters
        ----------
        respx_mock
            Mock router to use to install routes.
        base_url
            Base URL for the mock routes.
        """
        prefix = base_url.rstrip("/") + "/"
        handler = self._handle_user_info
        respx_mock.get(urljoin(prefix, "user-info")).mock(side_effect=handler)

        # These routes require regex matching of the username.
        base_regex = re.escape(base_url.rstrip("/"))
        regex = re.compile(base_regex + "/users/(?P<username>[^/]+)$")
        respx_mock.get(url__regex=regex).mock(side_effect=self._handle_user)

    def set_user_info(
        self, username: str, user_info: GafaelfawrUserInfo | None
    ) -> None:
        """Set the user information for a given user.

        Parameters
        ----------
        username
            Username for which to set a quota.
        user_info
            User information to return for that user, or `None` to return a
            404 error.
        """
        assert user_info is None or user_info.username == username, (
            f"User info for wrong user ({user_info.username} != {username}"
        )
        self._user_info[username] = user_info

    @staticmethod
    def _check[**P](
        *,
        fail_on: MockGafaelfawrAction | None = None,
        required_scope: str | None = None,
    ) -> Callable[
        [
            Callable[
                Concatenate[MockGafaelfawr, Request, GafaelfawrTokenData, P],
                Response,
            ]
        ],
        Callable[Concatenate[MockGafaelfawr, Request, P], Response],
    ]:
        """Wrap `MockGafaelfawr` methods to perform common checks.

        There are various common checks that should be performed for every
        request to the mock, and the token always has to be extracted from the
        requst and injected as an additional argument to the method. This
        wrapper performs those checks and then injects the token data into the
        underlying handler.

        Paramaters
        ----------
        fail_on
            If this user is configured to fail on this action, return a
            failure rather than calling the underlying handler.

        Returns
        -------
        typing.Callable
            Decorator to wrap `MockGafaelfawr` methods.
        """

        def decorator(
            f: Callable[
                Concatenate[MockGafaelfawr, Request, GafaelfawrTokenData, P],
                Response,
            ],
        ) -> Callable[Concatenate[MockGafaelfawr, Request, P], Response]:
            @wraps(f)
            def wrapper(
                mock: MockGafaelfawr,
                request: Request,
                *args: P.args,
                **kwargs: P.kwargs,
            ) -> Response:
                authorization = request.headers["Authorization"]
                scheme, token = authorization.split(None, 1)
                if scheme.lower() != "bearer":
                    return Response(403)
                token_data = mock._tokens.get(token)
                if not token_data:
                    return Response(403)
                if fail_on and fail_on in mock._fail[token_data.username]:
                    return Response(500)
                if required_scope and required_scope not in token_data.scopes:
                    return Response(403)
                return f(mock, request, token_data, *args, **kwargs)

            return wrapper

        return decorator

    @_check(required_scope="admin:userinfo")
    def _handle_user(
        self,
        request: Request,
        token_data: GafaelfawrTokenData,
        *,
        username: str,
    ) -> Response:
        if MockGafaelfawrAction.USER_INFO in self._fail[username]:
            return Response(500)
        elif user_info := self._user_info.get(username):
            result = user_info.model_dump(mode="json", exclude_defaults=True)
            return Response(200, json=result)
        else:
            return Response(404)

    @_check(fail_on=MockGafaelfawrAction.USER_INFO)
    def _handle_user_info(
        self, request: Request, token_data: GafaelfawrTokenData
    ) -> Response:
        if user_info := self._user_info.get(token_data.username):
            result = user_info.model_dump(mode="json", exclude_defaults=True)
            return Response(200, json=result)
        else:
            return Response(404)


async def register_mock_gafaelfawr(respx_mock: respx.Router) -> MockGafaelfawr:
    """Mock out Gafaelfawr.

    Parameters
    ----------
    respx_mock
        Mock router.

    Returns
    -------
    MockGafaelfawr
        Mock Gafaelfawr API object.
    """
    discovery_client = DiscoveryClient()
    url = await discovery_client.url_for_internal("gafaelfawr", version="v1")
    assert url, "Service gafaelfawr (v1) not found in Repertoire"
    mock = MockGafaelfawr()
    mock.install_routes(respx_mock, url)
    return mock
