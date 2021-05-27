"""Selenium tests for ``/auth/tokens``."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urljoin

from gafaelfawr.models.token import TokenType
from tests.pages.tokens import TokensPage

if TYPE_CHECKING:
    from seleniumwire import webdriver

    from tests.support.selenium import SeleniumConfig


def test_create_token(
    driver: webdriver.Chrome, selenium_config: SeleniumConfig
) -> None:
    driver.get(urljoin(selenium_config.url, "/auth/tokens"))

    tokens_page = TokensPage(driver)
    assert tokens_page.get_tokens(TokenType.user) == []
    session_tokens = tokens_page.get_tokens(TokenType.session)
    assert len(session_tokens) == 1
    assert session_tokens[0].token == selenium_config.token.key

    create_modal = tokens_page.click_create_token()
    create_modal.set_token_name("test token")
    create_modal.submit()

    new_token_modal = tokens_page.get_new_token_modal()
    assert new_token_modal.token.startswith("gt-")
    new_token_modal.dismiss()

    user_tokens = tokens_page.get_tokens(TokenType.user)
    assert len(user_tokens) == 1
    assert user_tokens[0].name == "test token"
