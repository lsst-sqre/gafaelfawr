"""Tests for token functions."""

from __future__ import annotations

from rubin.gafaelfawr import create_token


def test_create_token() -> None:
    token = create_token()
    assert token.startswith("gt-")
