"""Tests for gafaelfawr, the top-level import."""

import gafaelfawr


def test_version() -> None:
    assert isinstance(gafaelfawr.__version__, str)
