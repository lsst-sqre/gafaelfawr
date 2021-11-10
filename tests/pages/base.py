"""Base page model for Selenium tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import List, Union

    from selenium.webdriver.common.by import By
    from selenium.webdriver.remote.webelement import WebElement
    from seleniumwire import webdriver


class BaseFinder:
    def __init__(self, root: Union[webdriver.Chrome, WebElement]) -> None:
        self.root = root

    def find_element(self, by: By, name: str) -> WebElement:
        return self.root.find_element(by, name)

    def find_elements(self, by: By, name: str) -> List[WebElement]:
        return self.root.find_elements(by, name)


class BasePage(BaseFinder):
    def __init__(self, root: webdriver.Chrome) -> None:
        self.root = root

    @property
    def page_source(self) -> str:
        return self.root.page_source


class BaseModal(BaseFinder):
    def __init__(self, root: WebElement) -> None:
        self.root = root


class BaseElement(BaseFinder):
    def __init__(self, root: WebElement) -> None:
        self.root = root
