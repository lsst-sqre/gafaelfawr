"""Tests for jwt_authorizer, the top-level import."""

import jwt_authorizer


def test_version() -> None:
    assert isinstance(jwt_authorizer.__version__, str)
