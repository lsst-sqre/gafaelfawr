"""Tests for the service that handles token administrators."""

from __future__ import annotations

import pytest

from gafaelfawr.exceptions import PermissionDeniedError
from gafaelfawr.factory import Factory
from gafaelfawr.models.admin import Admin


@pytest.mark.asyncio
async def test_add(factory: Factory) -> None:
    admin_service = factory.create_admin_service()

    assert await admin_service.get_admins() == [Admin(username="admin")]
    await admin_service.add_admin(
        "example", actor="admin", ip_address="192.168.0.1"
    )
    assert await admin_service.get_admins() == [
        Admin(username="admin"),
        Admin(username="example"),
    ]

    with pytest.raises(PermissionDeniedError):
        await admin_service.add_admin(
            "foo", actor="bar", ip_address="127.0.0.1"
        )

    await admin_service.add_admin(
        "foo", actor="<bootstrap>", ip_address="127.0.0.1"
    )
    assert await admin_service.get_admins() == [
        Admin(username="admin"),
        Admin(username="example"),
        Admin(username="foo"),
    ]


@pytest.mark.asyncio
async def test_delete(factory: Factory) -> None:
    admin_service = factory.create_admin_service()
    assert await admin_service.get_admins() == [Admin(username="admin")]

    # Cannot delete the only admin.
    with pytest.raises(PermissionDeniedError):
        await admin_service.delete_admin(
            "admin", actor="admin", ip_address="127.0.0.1"
        )

    # Can delete the admin once there is another one.
    await admin_service.add_admin(
        "example", actor="admin", ip_address="127.0.0.1"
    )
    await admin_service.delete_admin(
        "admin", actor="admin", ip_address="127.0.0.1"
    )
    assert await admin_service.get_admins() == [Admin(username="example")]

    await admin_service.add_admin(
        "other", actor="example", ip_address="127.0.0.1"
    )
    await admin_service.delete_admin(
        "other", actor="<bootstrap>", ip_address="127.0.0.1"
    )
    assert await admin_service.get_admins() == [Admin(username="example")]
