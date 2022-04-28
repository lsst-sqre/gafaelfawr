"""Tests for the user information service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gafaelfawr.exceptions import MissingClaimsException
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.models.oidc import OIDCVerifiedToken
from tests.support.settings import configure


@pytest.mark.asyncio
async def test_missing_token_data(
    tmp_path: Path, factory: ComponentFactory
) -> None:
    config = await configure(tmp_path, "oidc")
    assert config.oidc
    factory.reconfigure(config)
    user_info = factory.create_oidc_user_info_service()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=24)
    token = OIDCVerifiedToken(
        encoded="some-encoded-token",
        claims={
            "aud": config.oidc.audience,
            "iat": int(now.timestamp()),
            "iss": config.oidc.issuer,
            "exp": int(exp.timestamp()),
        },
    )

    # Missing username claim.
    with pytest.raises(MissingClaimsException) as excinfo:
        await user_info.get_user_info_from_oidc_token(token)
    expected = f"No {config.oidc.username_claim} claim in token"
    assert str(excinfo.value) == expected

    # Missing UID claim.
    token.claims[config.oidc.username_claim] = "some-user"
    with pytest.raises(MissingClaimsException) as excinfo:
        await user_info.get_user_info_from_oidc_token(token)
    expected = f"No {config.oidc.uid_claim} claim in token"
    assert str(excinfo.value) == expected
