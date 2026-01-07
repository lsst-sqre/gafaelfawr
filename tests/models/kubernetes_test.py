"""Tests for Kubernetes models."""

import pytest
from pydantic import ValidationError

from gafaelfawr.models.auth import Satisfy
from gafaelfawr.models.kubernetes import (
    GafaelfawrIngressConfig,
    GafaelfawrIngressPathService,
)


def test_scopes() -> None:
    """Test handling of ``all`` and ``any`` in configured scopes."""
    config = GafaelfawrIngressConfig.model_validate(
        {"scopes": {"any": ["read:all", "read:some"]}}
    )
    assert config.scopes.satisfy == Satisfy.ANY
    assert config.scopes.scopes == ["read:all", "read:some"]

    config = GafaelfawrIngressConfig.model_validate(
        {"scopes": {"all": ["read:all", "read:some"]}}
    )
    assert config.scopes.satisfy == Satisfy.ALL
    assert config.scopes.scopes == ["read:all", "read:some"]

    config = GafaelfawrIngressConfig.model_validate({"scopes": {"all": []}})
    assert config.scopes.satisfy == Satisfy.ALL
    assert config.scopes.scopes == []

    config = GafaelfawrIngressConfig.model_validate({"scopes": {"any": []}})
    assert config.scopes.satisfy == Satisfy.ANY
    assert config.scopes.scopes == []

    with pytest.raises(ValidationError):
        config = GafaelfawrIngressConfig.model_validate(
            {
                "scopes": {
                    "all": ["read:all"],
                    "any": ["read:some", "read:image"],
                },
            }
        )

    with pytest.raises(ValidationError):
        GafaelfawrIngressConfig.model_validate({"scopes": {}})

    with pytest.raises(ValidationError):
        GafaelfawrIngressConfig.model_validate(
            {"scopes": {"all": [], "any": []}}
        )


def test_delegate() -> None:
    """Test handling of the two types of delegated tokens."""
    with pytest.raises(ValidationError) as excinfo:
        GafaelfawrIngressConfig.model_validate(
            {
                "scopes": {"all": ["read:all"]},
                "delegate": {
                    "notebook": {},
                    "internal": {"service": "foo", "scopes": []},
                },
            }
        )
    msg = str(excinfo.value)
    assert "only one of notebook and internal may be given" in msg

    with pytest.raises(ValidationError) as excinfo:
        GafaelfawrIngressConfig.model_validate(
            {"scopes": {"all": ["read:all"]}, "delegate": {}}
        )
    assert "one of notebook and internal must be given" in str(excinfo.value)


def test_service_port() -> None:
    with pytest.raises(ValidationError):
        GafaelfawrIngressPathService.model_validate(
            {"name": "", "port": {"name": "", "number": 0}}
        )

    with pytest.raises(ValidationError):
        GafaelfawrIngressPathService.model_validate({"name": "", "port": {}})


def test_basic_login_redirect() -> None:
    GafaelfawrIngressConfig.model_validate(
        {
            "authType": "bearer",
            "loginRedirect": True,
            "scopes": {"all": ["read:all"]},
        }
    )
    with pytest.raises(ValidationError):
        GafaelfawrIngressConfig.model_validate(
            {
                "authType": "basic",
                "loginRedirect": True,
                "scopes": {"all": ["read:all"]},
            }
        )


def test_anonymous() -> None:
    GafaelfawrIngressConfig.model_validate(
        {"authType": "basic", "scopes": {"all": ["read:all"]}}
    )
    with pytest.raises(ValidationError):
        GafaelfawrIngressConfig.model_validate(
            {"authType": "basic", "scopes": {"anonymous": True}}
        )
    GafaelfawrIngressConfig.model_validate(
        {"delegate": {"notebook": {}}, "scopes": {"all": ["read:all"]}}
    )
    with pytest.raises(ValidationError):
        GafaelfawrIngressConfig.model_validate(
            {"delegate": {"notebook": {}}, "scopes": {"anonymous": True}}
        )

    # Boolean fields should produce an error if set to true, but not if false.
    for field in ("loginRedirect", "replace403"):
        GafaelfawrIngressConfig.model_validate(
            {field: False, "scopes": {"anonymous": True}}
        )
        with pytest.raises(ValidationError):
            GafaelfawrIngressConfig.model_validate(
                {field: True, "scopes": {"anonymous": True}}
            )

    # allowCookeis should only produce an error if it's set to false.
    GafaelfawrIngressConfig.model_validate(
        {"allowCookies": True, "scopes": {"anonymous": True}}
    )
    with pytest.raises(ValidationError):
        GafaelfawrIngressConfig.model_validate(
            {"allowCookies": False, "scopes": {"anonymous": True}}
        )


def test_allow_cookies() -> None:
    GafaelfawrIngressConfig.model_validate(
        {"allowCookies": False, "scopes": {"all": ["read:all"]}}
    )
    with pytest.raises(ValidationError):
        GafaelfawrIngressConfig.model_validate(
            {
                "allowCookies": False,
                "loginRedirect": True,
                "scopes": {"all": ["read:all"]},
            }
        )
