"""Tests for user information models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gafaelfawr.models.userinfo import Group


def test_group_names() -> None:
    for valid in (
        "g_special_users",
        "rra",
        "19numbers",
        "G-12345",
        "group.name",
        "group1234",
        "19numbers19",
        "1-g",
        "12341-g-",
    ):
        Group(name=valid, id=1234)

    for invalid in ("12345", "rra#foo", "", "-rra", "_rra", "1-"):
        with pytest.raises(ValidationError):
            Group(name=invalid, id=1234)
