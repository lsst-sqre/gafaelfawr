"""Page models for token-related pages."""

from __future__ import annotations

from typing import TYPE_CHECKING

from selenium.common.exceptions import NoSuchElementException

from gafaelfawr.models.token import TokenType
from tests.pages.base import BaseElement, BaseModal, BasePage

if TYPE_CHECKING:
    from typing import List

    from selenium.webdriver.remote.webelement import WebElement


class TokensPage(BasePage):
    async def click_create_token(self) -> CreateTokenModal:
        button = self.find_element_by_id("qa-create-token")
        button.click()
        element = self.find_element_by_id("create-token-modal")
        return CreateTokenModal(element)

    def get_new_token_modal(self) -> NewTokenModal:
        element = self.find_element_by_id("qa-new-token-modal")
        return NewTokenModal(element)

    def get_tokens(self, token_type: TokenType) -> List[TokenRow]:
        try:
            table = self.find_element_by_id(f"tokens-{token_type.value}")
        except NoSuchElementException:
            return []
        return [
            TokenRow(e)
            for e in table.find_elements_by_class_name("qa-token-row")
        ]


class CreateTokenModal(BaseModal):
    @property
    def form(self) -> WebElement:
        return self.find_element_by_tag_name("form")

    def set_token_name(self, token_name: str) -> None:
        field = self.form.find_element_by_id("create-token-name")
        field.send_keys(token_name)

    async def submit(self) -> None:
        self.form.submit()


class NewTokenModal(BaseModal):
    @property
    def token(self) -> str:
        return self.find_element_by_id("qa-new-token").text

    def dismiss(self) -> None:
        button = self.find_element_by_id("token-accept")
        button.click()


class TokenRow(BaseElement):
    @property
    def name(self) -> str:
        return self.find_element_by_class_name("qa-token-name").text

    @property
    def token(self) -> str:
        return self.find_element_by_class_name("qa-token").text

    async def click_delete_token(self) -> None:
        button = self.find_element_by_class_name("qa-token-delete")
        button.click()
