"""pytest fixtures for testing."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from jwt_authorizer.app import create_app

if TYPE_CHECKING:
    from flask import Flask


@pytest.fixture(scope="session")
def app() -> Flask:
    app = create_app(FORCE_ENV_FOR_DYNACONF="testing")
    return app
