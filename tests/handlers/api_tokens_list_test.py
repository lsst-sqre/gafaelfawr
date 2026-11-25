"""Tests for the ``/auth/api/v1/tokens`` route for listing tokens."""

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
import pytest_asyncio
from httpx import AsyncClient
from safir.database import datetime_to_db
from safir.http import PaginationLinkData
from safir.testing.data import Data
from safir.testing.slack import MockSlackWebhook
from sqlalchemy import update

from gafaelfawr.config import Config
from gafaelfawr.factory import Factory
from gafaelfawr.models.token import Token, TokenData
from gafaelfawr.schema import Token as SQLToken

from ..support.constants import TEST_HOSTNAME
from ..support.tokens import create_session_token

URL = "/auth/api/v1/tokens"


@pytest_asyncio.fixture
async def admin_token(factory: Factory) -> TokenData:
    return await create_session_token(
        factory, username="some-admin", scopes={"admin:token"}
    )


@pytest_asyncio.fixture
async def tokens(
    *,
    client: AsyncClient,
    factory: Factory,
    data: Data,
    admin_token: TokenData,
) -> list[dict[str, Any]]:
    """Create tokens to list and return them as the API should.

    Returns
    -------
    list of dict
        Expected API representation of every token in the database, which
        is the tokens created here and the session token of the
        administrator. The order is not meaningful.
    """
    headers = {"Authorization": f"Bearer {admin_token.token}"}
    keys = [admin_token.token.key]
    for request in data.read_json("tokens/admin-requests"):
        r = await client.post(URL, json=request, headers=headers)
        assert r.status_code == 201
        keys.append(Token.from_str(r.json()["token"]).key)

    # All of the tokens were created within a second or two, so spread out
    # the creation times to make sorting by them meaningful. Each pair of
    # tokens shares a creation time so that the sort order depends on the
    # token key as well. There is no way to do this through the service.
    now = datetime.now(tz=UTC).replace(microsecond=0)
    async with factory.session.begin():
        for i, key in enumerate(keys):
            created = now - timedelta(seconds=5 * (i // 2))
            stmt = (
                update(SQLToken)
                .where(SQLToken.token == key)
                .values(created=datetime_to_db(created))
            )
            await factory.session.execute(stmt)

    token_service = factory.create_token_service()
    all_tokens = await token_service.list_tokens(admin_token)
    assert len(all_tokens) == len(keys)
    return [t.model_dump(mode="json", exclude_none=True) for t in all_tokens]


def sort_tokens(
    tokens: list[dict[str, Any]],
    *,
    sort: str = "created",
    order: str = "desc",
) -> list[dict[str, Any]]:
    """Sort tokens into the order the API should return them."""
    if sort == "username":
        return sorted(
            tokens,
            key=lambda t: (t["username"], t["created"], t["token"]),
            reverse=order == "desc",
        )
    else:
        return sorted(
            tokens,
            key=lambda t: (t["created"], t["token"]),
            reverse=order == "desc",
        )


def build_url(query: dict[str, Any]) -> str:
    """Build the URL for a query the way that Safir builds pagination URLs."""
    if not query:
        return URL
    return f"{URL}?{urlencode(query, doseq=True)}"


async def check_list(
    client: AsyncClient,
    admin_token: TokenData,
    query: dict[str, Any],
    expected: list[dict[str, Any]],
) -> None:
    """Run an unpaginated request and check the results."""
    headers = {"Authorization": f"Bearer {admin_token.token}"}
    r = await client.get(build_url(query), headers=headers)
    assert r.status_code == 200
    assert r.json() == expected
    assert "Link" not in r.headers
    assert "X-Total-Count" not in r.headers


async def check_pagination(
    client: AsyncClient,
    admin_token: TokenData,
    query: dict[str, Any],
    expected: list[dict[str, Any]],
) -> None:
    """Check paginated return values.

    Step through the paginated queries following the Link URLs and check at
    each point that the prev URL also returns correct data.
    """
    headers = {"Authorization": f"Bearer {admin_token.token}"}
    limit = 3
    assert len(expected) > limit
    url = build_url({**query, "limit": limit})
    first_url = f"https://{TEST_HOSTNAME}{url}"
    count = str(len(expected))

    # First, walk forward and check next URLs and previous URLs as we go.
    prev_data = None
    all_data = []
    for end in range(limit, len(expected) + limit, limit):
        r = await client.get(url, headers=headers)
        assert r.status_code == 200
        seen = r.json()
        assert seen == expected[end - limit : end]
        assert r.headers["X-Total-Count"] == count

        # Check the Link contents, except for the next URL, which we'll check
        # by using it to retrieve the next data.
        link_data = PaginationLinkData.from_header(r.headers["Link"])
        assert link_data.first_url == first_url
        if end == limit:
            assert not link_data.prev_url
        else:
            assert link_data.prev_url
            r = await client.get(link_data.prev_url, headers=headers)
            assert r.status_code == 200
            assert r.json() == prev_data
            assert r.headers["X-Total-Count"] == count
            prev_link_data = PaginationLinkData.from_header(r.headers["Link"])
            assert prev_link_data.first_url == first_url
            assert prev_link_data.next_url == url

        # Save the data for previous URL checks.
        prev_data = seen
        all_data.extend(seen)

        # If we're not done, move to the next URL.
        if end < len(expected):
            assert link_data.next_url
            url = link_data.next_url

    # Should be no next URL for the last batch of data.
    assert not link_data.next_url
    assert all_data == expected

    # seen contains the last batch of data. Walking backwards using previous
    # URLs, we should be able to reconstruct all of the data and have it
    # match. This tests the previous URLs generated after following previous
    # URLs.
    backwards_data = seen
    while link_data.prev_url:
        r = await client.get(link_data.prev_url, headers=headers)
        assert r.status_code == 200
        assert r.headers["X-Total-Count"] == count
        backwards_data = r.json() + backwards_data
        link_data = PaginationLinkData.from_header(r.headers["Link"])
    assert backwards_data == expected


@pytest.mark.asyncio
async def test_filters(
    *,
    client: AsyncClient,
    config: Config,
    data: Data,
    admin_token: TokenData,
    tokens: list[dict[str, Any]],
) -> None:
    # With no parameters, tokens of all types are returned, newest first.
    all_tokens = sort_tokens(tokens)
    assert {t["token_type"] for t in all_tokens} == {
        "service",
        "session",
        "user",
    }
    await check_list(client, admin_token, {}, all_tokens)

    # The bootstrap token can also list tokens.
    bootstrap_token = config.bootstrap_token.get_secret_value()
    r = await client.get(
        URL, headers={"Authorization": f"Bearer {bootstrap_token}"}
    )
    assert r.status_code == 200
    assert r.json() == all_tokens

    # Limit the listing to service tokens and compare the result to the
    # expected output to check its format. The token keys and creation times
    # in the expected output are wildcards.
    service = [t for t in all_tokens if t["token_type"] == "service"]
    r = await client.get(
        URL,
        params={"token_type": "service", "sort": "username", "order": "asc"},
        headers={"Authorization": f"Bearer {admin_token.token}"},
    )
    assert r.status_code == 200
    assert r.json() == sort_tokens(service, sort="username", order="asc")
    data.assert_json_matches(r.json(), "tokens/list-service")
    await check_list(
        client,
        admin_token,
        {"token_type": "user"},
        [t for t in all_tokens if t["token_type"] == "user"],
    )
    await check_list(client, admin_token, {"token_type": "notebook"}, [])

    # Filter by username.
    await check_list(
        client,
        admin_token,
        {"username": "bot-mobu"},
        [t for t in all_tokens if t["username"] == "bot-mobu"],
    )
    await check_list(
        client,
        admin_token,
        {"username": "bot-mobu", "token_type": "user"},
        [],
    )

    # Filter by username prefix. A prefix does not have to be a valid
    # username and matches only at the start of the username.
    await check_list(
        client,
        admin_token,
        {"username_prefix": "bot-mobu"},
        [t for t in all_tokens if t["username"].startswith("bot-mobu")],
    )
    await check_list(
        client,
        admin_token,
        {"username_prefix": "bot-", "token_type": "service"},
        service,
    )
    await check_list(
        client,
        admin_token,
        {"username_prefix": "p"},
        [t for t in all_tokens if t["username"] == "paul"],
    )
    await check_list(client, admin_token, {"username_prefix": "mobu"}, [])

    # Filter by scope. A token matches if it has all of the given scopes,
    # whatever other scopes it has, and a scope must match in full.
    await check_list(
        client,
        admin_token,
        {"scope": "read:all"},
        [t for t in all_tokens if "read:all" in t["scopes"]],
    )
    both = {"exec:test", "read:all"}
    await check_list(
        client,
        admin_token,
        {"scope": ["read:all", "exec:test"]},
        [t for t in all_tokens if both <= set(t["scopes"])],
    )
    await check_list(
        client,
        admin_token,
        {"scope": "admin:token", "token_type": "service"},
        [t for t in service if "admin:token" in t["scopes"]],
    )
    await check_list(
        client,
        admin_token,
        {"scope": ["read:all", "exec:test"], "username_prefix": "bot-mobu"},
        [t for t in all_tokens if t["username"] == "bot-mobu"],
    )
    await check_list(client, admin_token, {"scope": "read"}, [])
    await check_list(client, admin_token, {"scope": "admin:userinfo"}, [])


@pytest.mark.asyncio
async def test_sort(
    *,
    client: AsyncClient,
    admin_token: TokenData,
    tokens: list[dict[str, Any]],
) -> None:
    for sort in ("created", "username"):
        for order in ("asc", "desc"):
            expected = sort_tokens(tokens, sort=sort, order=order)
            query = {"sort": sort, "order": order}
            await check_list(client, admin_token, query, expected)

    # The default order is descending whatever the sort field, and the
    # default sort field is the creation time.
    await check_list(
        client,
        admin_token,
        {"sort": "username"},
        sort_tokens(tokens, sort="username", order="desc"),
    )
    await check_list(
        client,
        admin_token,
        {"order": "asc"},
        sort_tokens(tokens, sort="created", order="asc"),
    )

    # Usernames are sorted by code point, so a hyphen sorts before a digit
    # or a letter, whatever the locale of the database.
    service = [t for t in tokens if t["token_type"] == "service"]
    expected = sort_tokens(service, sort="username", order="asc")
    assert [t["username"] for t in expected] == [
        "bot-a-service",
        "bot-ab",
        "bot-mobu",
        "bot-mobu",
        "bot-mobu-tap",
        "bot-mobu2",
        "bot-nublado",
    ]
    await check_list(
        client,
        admin_token,
        {"token_type": "service", "sort": "username", "order": "asc"},
        expected,
    )

    # Sorting applies to a filtered listing.
    mobu = [t for t in tokens if t["username"].startswith("bot-mobu")]
    await check_list(
        client,
        admin_token,
        {"username_prefix": "bot-mobu", "sort": "created", "order": "asc"},
        sort_tokens(mobu, sort="created", order="asc"),
    )


@pytest.mark.asyncio
async def test_pagination(
    *,
    client: AsyncClient,
    admin_token: TokenData,
    tokens: list[dict[str, Any]],
) -> None:
    # The default sort order, which is by creation time, newest first.
    await check_pagination(client, admin_token, {}, sort_tokens(tokens))

    # Every sort order, over all tokens.
    for sort in ("created", "username"):
        for order in ("asc", "desc"):
            expected = sort_tokens(tokens, sort=sort, order=order)
            await check_pagination(
                client, admin_token, {"sort": sort, "order": order}, expected
            )

    # Filters, including a repeated one, are kept in the pagination links.
    filtered = [
        t
        for t in tokens
        if t["token_type"] == "service" and "read:all" in t["scopes"]
    ]
    for sort in ("created", "username"):
        query: dict[str, Any] = {
            "token_type": "service",
            "scope": ["read:all"],
            "sort": sort,
            "order": "asc",
        }
        expected = sort_tokens(filtered, sort=sort, order="asc")
        await check_pagination(client, admin_token, query, expected)
    mobu = [t for t in tokens if t["username"].startswith("bot-mobu")]
    await check_pagination(
        client,
        admin_token,
        {"username_prefix": "bot-mobu", "sort": "username"},
        sort_tokens(mobu, sort="username", order="desc"),
    )

    # A limit larger than the number of tokens returns all of them with the
    # pagination headers but no links to other pages.
    headers = {"Authorization": f"Bearer {admin_token.token}"}
    r = await client.get(URL, params={"limit": 100}, headers=headers)
    assert r.status_code == 200
    assert r.json() == sort_tokens(tokens)
    assert r.headers["X-Total-Count"] == str(len(tokens))
    link_data = PaginationLinkData.from_header(r.headers["Link"])
    assert not link_data.next_url
    assert not link_data.prev_url


@pytest.mark.asyncio
async def test_invalid(
    *,
    client: AsyncClient,
    admin_token: TokenData,
    tokens: list[dict[str, Any]],
    mock_slack: MockSlackWebhook,
) -> None:
    headers = {"Authorization": f"Bearer {admin_token.token}"}

    # A username and a username prefix cannot be combined.
    r = await client.get(
        URL,
        params={"username": "bot-mobu", "username_prefix": "bot-"},
        headers=headers,
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "conflicting_filters"
    assert r.json()["detail"][0]["loc"] == ["query", "username_prefix"]

    # A username prefix cannot contain LIKE wildcards.
    for prefix in ("bot_", "bot-%", "%"):
        r = await client.get(
            URL, params={"username_prefix": prefix}, headers=headers
        )
        assert r.status_code == 422

    # Get a cursor for each sort field.
    cursors = {}
    for sort in ("created", "username"):
        r = await client.get(
            URL, params={"sort": sort, "limit": 3}, headers=headers
        )
        assert r.status_code == 200
        link_data = PaginationLinkData.from_header(r.headers["Link"])
        assert link_data.next_url
        query = parse_qs(urlparse(link_data.next_url).query)
        cursors[sort] = query["cursor"][0]

    # A cursor is only valid for the sort field of the listing that
    # returned it, whether as a next or a previous cursor.
    for sort, other in (("created", "username"), ("username", "created")):
        for cursor in (cursors[other], "p" + cursors[other]):
            r = await client.get(
                URL,
                params={"sort": sort, "limit": 3, "cursor": cursor},
                headers=headers,
            )
            assert r.status_code == 422
            assert r.json()["detail"][0]["type"] == "invalid_cursor"
            assert r.json()["detail"][0]["loc"] == ["query", "cursor"]

    # Malformed cursors are rejected.
    for cursor in ("foo", "1614985055_4234", "nan_" + "a" * 22):
        r = await client.get(URL, params={"cursor": cursor}, headers=headers)
        assert r.status_code == 422
        assert r.json()["detail"][0]["type"] == "invalid_cursor"

    # Only the creation time and the username are supported for sorting.
    r = await client.get(URL, params={"sort": "last_used"}, headers=headers)
    assert r.status_code == 422

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_admin_required(
    client: AsyncClient, factory: Factory, mock_slack: MockSlackWebhook
) -> None:
    r = await client.get(URL)
    assert r.status_code == 401

    # A user without admin:token cannot list tokens, even only their own.
    token_data = await create_session_token(factory, scopes={"user:token"})
    headers = {"Authorization": f"Bearer {token_data.token}"}
    r = await client.get(URL, headers=headers)
    assert r.status_code == 403
    r = await client.get(
        URL, params={"username": token_data.username}, headers=headers
    )
    assert r.status_code == 403

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []
