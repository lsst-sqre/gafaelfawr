"""Page models for token-related pages."""

from __future__ import annotations

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from gafaelfawr.models.token import TokenType

from .base import BaseElement, BaseModal, BasePage


class TokensPage(BasePage):
    """Representation of the user's token page for Selenium testing."""

    def click_create_token(self) -> CreateTokenModal:
        button = self.find_element(By.ID, "qa-create-token")
        button.click()
        element = self.find_element(By.ID, "create-token-modal")
        return CreateTokenModal(element)

    def get_new_token_modal(self) -> NewTokenModal:
        element = self.find_element(By.ID, "qa-new-token-modal")
        return NewTokenModal(element)

    def get_tokens(self, token_type: TokenType) -> list[TokenRow]:
        try:
            table = self.find_element(By.ID, f"tokens-{token_type.value}")
        except NoSuchElementException:
            return []
        return [
            TokenRow(e)
            for e in table.find_elements(By.CLASS_NAME, "qa-token-row")
        ]


class CreateTokenModal(BaseModal):
    """Representation of the create token modal for Selenium testing."""

    @property
    def form(self) -> WebElement:
        return self.find_element(By.TAG_NAME, "form")

    def set_token_name(self, token_name: str) -> None:
        field = self.form.find_element(By.ID, "create-token-name")
        field.send_keys(token_name)

    def submit(self) -> None:
        self.form.submit()


class NewTokenModal(BaseModal):
    """Representation of the new token modal for Selenium testing."""

    @property
    def token(self) -> str:
        return self.find_element(By.ID, "qa-new-token").text

    def dismiss(self) -> None:
        button = self.find_element(By.ID, "token-accept")
        button.click()


class TokenRow(BaseElement):
    """Representation of one token on the token page for Selenium testing."""

    @property
    def expires(self) -> str:
        return self.find_element(By.CLASS_NAME, "qa-expires").text

    @property
    def name(self) -> str:
        return self.find_element(By.CLASS_NAME, "qa-token-name").text

    @property
    def token(self) -> str:
        return self.find_element(By.CLASS_NAME, "qa-token").text

    def click_token(self) -> None:
        token = self.find_element(By.CLASS_NAME, "qa-token")
        token.click()

    def click_delete_token(self) -> None:
        button = self.find_element(By.CLASS_NAME, "qa-token-delete")
        button.click()


class TokenDataPage(BasePage):
    """Representation of the details page for a token for Selenium testing."""

    @property
    def expires(self) -> str:
        return self.find_element(By.CLASS_NAME, "qa-expires").text

    @property
    def scopes(self) -> str:
        return self._data.find_element(By.CLASS_NAME, "qa-scopes").text

    @property
    def token_type(self) -> str:
        return self._data.find_element(By.CLASS_NAME, "qa-type").text

    @property
    def username(self) -> str:
        return self._data.find_element(By.CLASS_NAME, "qa-username").text

    @property
    def _data(self) -> WebElement:
        return self.find_element(By.CLASS_NAME, "qa-token-data")

    def get_change_history(self) -> list[TokenChangeRow]:
        return [
            TokenChangeRow(e)
            for e in self.find_elements(By.CLASS_NAME, "qa-token-change-row")
        ]


class TokenChangeRow(BaseElement):
    """Representation of token change history for Selenium testing."""

    @property
    def action(self) -> str:
        return self.find_element(By.CLASS_NAME, "qa-action").text

    @property
    def expires(self) -> str:
        return self.find_element(By.CLASS_NAME, "qa-expires").text

    @property
    def scopes(self) -> str:
        return self.find_element(By.CLASS_NAME, "qa-scopes").text

    @property
    def token(self) -> str:
        return self.find_element(By.CLASS_NAME, "qa-token").text

    @property
    def token_type(self) -> str:
        return self.find_element(By.CLASS_NAME, "qa-type").text
