"""Tests for the service that handles token administrators."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gafaelfawr.exceptions import PermissionDeniedError
from gafaelfawr.models.admin import Admin

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


def test_add(setup: SetupTest) -> None:
    admin_service = setup.factory.create_admin_service()

    assert admin_service.get_admins() == [Admin(username="admin")]

    admin_service.add_admin("example", actor="admin", ip_address="192.168.0.1")

    assert admin_service.get_admins() == [
        Admin(username="admin"),
        Admin(username="example"),
    ]
    assert admin_service.is_admin("example")
    assert not admin_service.is_admin("foo")

    with pytest.raises(PermissionDeniedError):
        admin_service.add_admin("foo", actor="bar", ip_address="127.0.0.1")

    admin_service.add_admin("foo", actor="<bootstrap>", ip_address="127.0.0.1")
    assert admin_service.is_admin("foo")
    assert not admin_service.is_admin("<bootstrap>")


def test_delete(setup: SetupTest) -> None:
    admin_service = setup.factory.create_admin_service()

    assert admin_service.get_admins() == [Admin(username="admin")]

    with pytest.raises(PermissionDeniedError):
        admin_service.delete_admin(
            "admin", actor="admin", ip_address="127.0.0.1"
        )

    admin_service.add_admin("example", actor="admin", ip_address="127.0.0.1")
    admin_service.delete_admin("admin", actor="admin", ip_address="127.0.0.1")
    assert admin_service.is_admin("example")
    assert not admin_service.is_admin("admin")
    assert admin_service.get_admins() == [Admin(username="example")]

    admin_service.add_admin("other", actor="example", ip_address="127.0.0.1")
    admin_service.delete_admin(
        "other", actor="<bootstrap>", ip_address="127.0.0.1"
    )
    assert admin_service.get_admins() == [Admin(username="example")]
