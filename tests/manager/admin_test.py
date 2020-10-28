"""Tests for the token administrator manager class."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.models.admin import Admin

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


def test_admin_manager(setup: SetupTest) -> None:
    admin_manager = setup.factory.create_admin_manager()

    assert admin_manager.get_admins() == []

    admin_manager.add_admin("example", actor="admin", ip_address="192.168.0.1")

    assert admin_manager.get_admins() == [Admin(username="example")]
    assert admin_manager.is_admin("example")
    assert not admin_manager.is_admin("foo")
