"""Tests for Kubernetes models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gafaelfawr.models.auth import Satisfy
from gafaelfawr.models.kubernetes import (
    GafaelfawrIngressConfig,
    GafaelfawrIngressPathService,
)


def test_scopes() -> None:
    """Test handling of ``all`` and ``any`` in configured scopes."""
    config = GafaelfawrIngressConfig.parse_obj(
        {
            "baseUrl": "https://example.com/",
            "scopes": {"any": ["read:all", "read:some"]},
        }
    )
    assert config.scopes.satisfy == Satisfy.ANY
    assert config.scopes.scopes == ["read:all", "read:some"]

    config = GafaelfawrIngressConfig.parse_obj(
        {
            "baseUrl": "https://example.com/",
            "scopes": {"all": ["read:all", "read:some"]},
        }
    )
    assert config.scopes.satisfy == Satisfy.ALL
    assert config.scopes.scopes == ["read:all", "read:some"]

    config = GafaelfawrIngressConfig.parse_obj(
        {"baseUrl": "https://example.com/", "scopes": {"all": []}}
    )
    assert config.scopes.satisfy == Satisfy.ALL
    assert config.scopes.scopes == []

    config = GafaelfawrIngressConfig.parse_obj(
        {"baseUrl": "https://example.com/", "scopes": {"any": []}}
    )
    assert config.scopes.satisfy == Satisfy.ANY
    assert config.scopes.scopes == []

    with pytest.raises(ValidationError):
        config = GafaelfawrIngressConfig.parse_obj(
            {
                "baseUrl": "https://example.com/",
                "scopes": {
                    "all": ["read:all"],
                    "any": ["read:some", "read:image"],
                },
            }
        )
        print(type(config.scopes))

    with pytest.raises(ValidationError):
        GafaelfawrIngressConfig.parse_obj(
            {"baseUrl": "https://example.com/", "scopes": {}}
        )

    with pytest.raises(ValidationError):
        GafaelfawrIngressConfig.parse_obj(
            {
                "baseUrl": "https://example.com/",
                "scopes": {"all": [], "any": []},
            }
        )


def test_delegate() -> None:
    """Test handling of the two types of delegated tokens."""
    with pytest.raises(ValidationError) as excinfo:
        GafaelfawrIngressConfig.parse_obj(
            {
                "baseUrl": "https://example.com/",
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
        GafaelfawrIngressConfig.parse_obj(
            {
                "baseUrl": "https://example.com/",
                "scopes": {"all": ["read:all"]},
                "delegate": {},
            }
        )
    assert "one of notebook and internal must be given" in str(excinfo.value)


def test_service_port() -> None:
    with pytest.raises(ValidationError):
        GafaelfawrIngressPathService.parse_obj(
            {"name": "", "port": {"name": "", "number": 0}}
        )

    with pytest.raises(ValidationError):
        GafaelfawrIngressPathService.parse_obj({"name": "", "port": {}})
