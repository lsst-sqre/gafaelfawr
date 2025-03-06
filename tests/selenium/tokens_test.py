"""Selenium tests for ``/auth/tokens``."""

from __future__ import annotations

from urllib.parse import urljoin

import pytest
from httpx import AsyncClient
from seleniumwire import webdriver

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.models.enums import TokenType
from gafaelfawr.models.state import State
from gafaelfawr.models.token import Token

from ..pages.tokens import TokenDataPage, TokensPage
from ..support.selenium import SeleniumConfig


@pytest.mark.asyncio
async def test_create_token(
    driver: webdriver.Chrome, selenium_config: SeleniumConfig
) -> None:
    driver.get(urljoin(selenium_config.url, "/auth/tokens"))

    tokens_page = TokensPage(driver)
    assert tokens_page.get_tokens(TokenType.user) == []
    session_tokens = tokens_page.get_tokens(TokenType.session)
    assert len(session_tokens) == 2
    assert any(
        t for t in session_tokens if t.token == selenium_config.token.key
    )

    create_modal = tokens_page.click_create_token()
    create_modal.set_token_name("test token")
    create_modal.submit()

    new_token_modal = tokens_page.get_new_token_modal()
    assert new_token_modal.token.startswith("gt-")
    new_token_modal.dismiss()

    user_tokens = tokens_page.get_tokens(TokenType.user)
    assert len(user_tokens) == 1
    assert user_tokens[0].name == "test token"


@pytest.mark.asyncio
async def test_token_info(
    driver: webdriver.Chrome, selenium_config: SeleniumConfig
) -> None:
    cookie = State(token=selenium_config.token).to_cookie()

    # Create a notebook token and an internal token.
    async with AsyncClient() as client:
        r = await client.get(
            urljoin(selenium_config.url, "/ingress/auth"),
            params={"scope": "exec:test", "notebook": "true"},
            headers={
                "Cookie": f"{COOKIE_NAME}={cookie}",
                "X-Original-Method": "GET",
                "X-Original-URL": "https://foo.example.com/bar",
            },
        )
        assert r.status_code == 200
        notebook_token = Token.from_str(r.headers["X-Auth-Request-Token"])
        r = await client.get(
            urljoin(selenium_config.url, "/ingress/auth"),
            params={"scope": "exec:test", "delegate_to": "service"},
            headers={
                "Cookie": f"{COOKIE_NAME}={cookie}",
                "X-Original-Method": "GET",
                "X-Original-URL": "https://foo.example.com/bar",
            },
        )
        assert r.status_code == 200
        internal_token = Token.from_str(r.headers["X-Auth-Request-Token"])

    # Load the token page and go to the history for our session token.
    driver.get(urljoin(selenium_config.url, "/auth/tokens"))
    tokens_page = TokensPage(driver)
    session_tokens = tokens_page.get_tokens(TokenType.session)
    session_token = next(
        t for t in session_tokens if t.token == selenium_config.token.key
    )
    session_token.click_token()

    # We should now be at the token information page for the session token.
    data_page = TokenDataPage(driver)
    assert data_page.username == "testuser"
    assert data_page.token_type == "session"
    scopes = sorted(selenium_config.config.known_scopes.keys())
    assert data_page.scopes == ", ".join(scopes)
    history = data_page.get_change_history()
    assert len(history) == 3
    assert history[0].action == "create"
    assert history[0].token == internal_token.key
    assert not history[0].scopes
    assert history[1].action == "create"
    assert history[1].token == notebook_token.key
    assert history[1].scopes == ", ".join(scopes)
    assert history[2].action == "create"
    assert history[2].token == selenium_config.token.key
    assert history[2].scopes == ", ".join(scopes)


@pytest.mark.asyncio
async def test_expired_token(
    driver: webdriver.Chrome, selenium_config: SeleniumConfig
) -> None:
    driver.get(urljoin(selenium_config.url, "/auth/tokens"))
    tokens_page = TokensPage(driver)
    session_tokens = tokens_page.get_tokens(TokenType.session)

    # Find the expired token, which is the one that doesn't match the one
    # returned by the selenium configuration.
    session_token = next(
        t for t in session_tokens if t.token != selenium_config.token.key
    )
    token = session_token.token

    # Check that the expiration time is displayed correctly.
    assert session_token.expires == "expired"

    # Go to the token page and check that the expiration there and in the
    # history is also correct.
    session_token.click_token()
    data_page = TokenDataPage(driver)
    assert data_page.username == "testuser"
    assert data_page.token_type == "session"
    scopes = sorted(selenium_config.config.known_scopes.keys())
    assert data_page.scopes == ", ".join(scopes)
    assert data_page.expires == "expired"
    history = data_page.get_change_history()
    assert len(history) == 1
    assert history[0].action == "create"
    assert history[0].token == token
    assert history[0].expires == "expired"
