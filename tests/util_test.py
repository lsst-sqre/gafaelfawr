"""Tests for the jwt_authorizer.tokens package."""

from __future__ import annotations

from jwt_authorizer.util import add_padding


def test_add_padding() -> None:
    assert add_padding("") == ""
    assert add_padding("Zg") == "Zg=="
    assert add_padding("Zgo") == "Zgo="
    assert add_padding("Zm8K") == "Zm8K"
    assert add_padding("Zm9vCg") == "Zm9vCg=="
