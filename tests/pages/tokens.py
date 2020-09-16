"""Page models for token-related pages."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from tests.pages.base import BaseElement, BasePage
from tests.support.selenium import run

if TYPE_CHECKING:
    from typing import List, Optional

    from selenium.webdriver.remote.webelement import WebElement


class NewTokenPage(BasePage):
    @property
    def form(self) -> WebElement:
        return self.find_element_by_id("create-token")

    @property
    def scopes(self) -> List[ScopeRow]:
        return [
            ScopeRow(e)
            for e in self.find_elements_by_class_name("token-scope")
        ]

    async def submit(self) -> None:
        button = self.form.find_element_by_id("submit")
        await run(button.click)


class TokensPage(BasePage):
    @property
    def new_token(self) -> Optional[str]:
        alert = self.find_elements_by_class_name("alert")
        if not alert:
            return None
        match = re.search("Token: ([^ ]+)", alert[0].text)
        if match:
            return match.group(1)
        else:
            return None

    @property
    def tokens(self) -> List[TokenRow]:
        return [
            TokenRow(e) for e in self.find_elements_by_class_name("token-row")
        ]

    async def click_create_token(self) -> None:
        button = self.find_element_by_id("new-token")
        await run(button.click)


class ScopeRow(BaseElement):
    @property
    def checkbox(self) -> WebElement:
        return self.find_element_by_class_name("form-check-input")

    @property
    def description(self) -> str:
        return self.find_element_by_class_name("scope-description").text

    @property
    def label(self) -> str:
        return self.find_element_by_class_name("form-check-label").text


class TokenRow(BaseElement):
    @property
    def key(self) -> str:
        return self.find_element_by_class_name("token-link").text

    @property
    def link(self) -> str:
        token_link = self.find_element_by_class_name("token-link")
        return token_link.find_element_by_tag_name("a").get_attribute("href")

    @property
    def scope(self) -> str:
        return self.find_element_by_class_name("token-scope").text
