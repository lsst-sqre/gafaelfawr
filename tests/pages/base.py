"""Base page model for Selenium tests."""

from __future__ import annotations

from selenium import webdriver
from selenium.webdriver.remote.webelement import WebElement

__all__ = [
    "BaseElement",
    "BaseModal",
    "BasePage",
]


class BasePage:
    """Wrapper around a web page for Selenium testing."""

    def __init__(self, root: webdriver.Chrome) -> None:
        self.root = root

    @property
    def page_source(self) -> str:
        return self.root.page_source

    def find_element(self, by: str, name: str) -> WebElement:
        return self.root.find_element(by, name)

    def find_elements(self, by: str, name: str) -> list[WebElement]:
        return self.root.find_elements(by, name)


class BaseElement:
    """Wrapper around a page element for Selenium testing."""

    def __init__(self, root: WebElement) -> None:
        self.root = root

    def find_element(self, by: str, name: str) -> WebElement:
        return self.root.find_element(by, name)

    def find_elements(self, by: str, name: str) -> list[WebElement]:
        return self.root.find_elements(by, name)


class BaseModal(BaseElement):
    """Wrapper around a page modal dialogue for Selenium testing."""
