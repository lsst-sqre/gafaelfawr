"""Base page model for Selenium tests."""

from __future__ import annotations

from typing import List

from selenium.webdriver.remote.webelement import WebElement
from seleniumwire import webdriver


class BasePage:
    def __init__(self, root: webdriver.Chrome) -> None:
        self.root = root

    @property
    def page_source(self) -> str:
        return self.root.page_source

    def find_element(self, by: str, name: str) -> WebElement:
        return self.root.find_element(by, name)

    def find_elements(self, by: str, name: str) -> List[WebElement]:
        return self.root.find_elements(by, name)


class BaseElement:
    def __init__(self, root: WebElement) -> None:
        self.root = root

    def find_element(self, by: str, name: str) -> WebElement:
        return self.root.find_element(by, name)

    def find_elements(self, by: str, name: str) -> List[WebElement]:
        return self.root.find_elements(by, name)


class BaseModal(BaseElement):
    pass
