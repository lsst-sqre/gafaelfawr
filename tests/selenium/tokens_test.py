"""Selenium tests for ``/auth/tokens``."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urljoin

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.models.state import State
from gafaelfawr.models.token import TokenType
from tests.pages.tokens import TokensPage

if TYPE_CHECKING:
    from seleniumwire import webdriver

    from tests.support.selenium import SeleniumConfig


def test_create_token(
    driver: webdriver.Chrome, selenium_config: SeleniumConfig
) -> None:
    cookie = State(token=selenium_config.token).as_cookie()
    driver.header_overrides = {"Cookie": f"{COOKIE_NAME}={cookie}"}

    tokens_url = urljoin(selenium_config.url, "/auth/tokens")
    driver.get(tokens_url)

    tokens_page = TokensPage(driver)
    assert tokens_page.get_tokens(TokenType.user) == []
    session_tokens = tokens_page.get_tokens(TokenType.session)
    assert len(session_tokens) == 1
    assert session_tokens[0].token == selenium_config.token.key

    # Drop our cookie in favor of the one the browser is now sending, since
    # the browser one contains a CSRF token that will be required for token
    # creation.
    del driver.header_overrides

    create_modal = tokens_page.click_create_token()
    create_modal.set_token_name("test token")
    create_modal.submit()

    new_token_modal = tokens_page.get_new_token_modal()
    assert new_token_modal.token.startswith("gt-")
    new_token_modal.dismiss()

    user_tokens = tokens_page.get_tokens(TokenType.user)
    assert len(user_tokens) == 1
    assert user_tokens[0].name == "test token"
