"""ForgeRock Identity Management API mocks for testing."""

from __future__ import annotations

import re
from base64 import b64encode
from urllib.parse import parse_qs

import respx
from httpx import Request, Response

from gafaelfawr.config import Config

__all__ = ["MockForgeRock", "mock_forgerock"]


class MockForgeRock:
    """Pretends to be the ForgeRock API for testing.

    The methods of this object should be installed as respx mock side effects
    using `mock_forgerock`.

    Parameters
    ----------
    username
        Expected authentication username.
    password
        Expected authentication password.
    groups
        Mapping of group names to GIDs to return. If the group is unknown,
        the mocked API will return an empty list.

    Attributes
    ----------
    groups
        Mapping of group names to GIDs to return.
    """

    def __init__(
        self, username: str, password: str, groups: dict[str, int]
    ) -> None:
        self._username = username
        self._password = password
        self.groups = groups

    def get_gid(self, request: Request) -> Response:
        basic_auth = b64encode(f"{self._username}:{self._password}".encode())
        auth_header = f"Basic {basic_auth.decode()}"
        assert request.headers["Authorization"] == auth_header

        query = parse_qs(request.url.query)
        assert set(query.keys()) == {b"_fields", b"_queryFilter"}
        assert query[b"_fields"] == [b"gid"]
        assert len(query[b"_queryFilter"]) == 1
        query_filter = query[b"_queryFilter"][0].decode()
        match = re.match(r'name eq "([^"]+)"$', query_filter)
        assert match
        group = match.group(1)

        if group in self.groups:
            response = {"result": [{"gid": self.groups[group]}]}
            return Response(200, json=response)
        else:
            return Response(200, json={"result": []})


def mock_forgerock(
    config: Config, respx_mock: respx.Router, groups: dict[str, int]
) -> MockForgeRock:
    """Set up the mocks for a ForgeRock GID lookup.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    respx_mock
        The mock router.
    groups
        Mapping of valid group names to GIDs.
    """
    assert config.forgerock
    url = config.forgerock.url.rstrip("/") + "/system/freeipa/group"
    mock = MockForgeRock(
        config.forgerock.username, config.forgerock.password, groups
    )
    respx_mock.get(url__startswith=url).mock(side_effect=mock.get_gid)
    return mock
