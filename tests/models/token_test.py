"""Tests for the gafaelfawr.session package."""

import pytest
from pydantic import ValidationError

from gafaelfawr.exceptions import InvalidTokenError
from gafaelfawr.models.enums import TokenType
from gafaelfawr.models.token import AdminTokenRequest, Token


def test_token() -> None:
    token = Token()
    assert str(token).startswith("gt-")


def test_token_from_str() -> None:
    bad_tokens = [
        "",
        ".",
        "MLF5MB3Peg79wEC0BY8U8Q",
        "MLF5MB3Peg79wEC0BY8U8Q.",
        "gt-",
        "gt-.",
        "gt-MLF5MB3Peg79wEC0BY8U8Q",
        "gt-MLF5MB3Peg79wEC0BY8U8Q.",
        "gt-.ChbkqEyp3EIJ2e_1Sqff3w",
        "gt-NOT.VALID",
        "gt-MLF5MB3Peg79wEC0BY8U8Q.ChbkqEyp3EIJ2e_1Sqff3w.!!!!",
        "gtMLF5MB3Peg79wEC0BY8U8Q.ChbkqEyp3EIJ2e_1Sqff3w",
    ]
    for token_str in bad_tokens:
        with pytest.raises(InvalidTokenError):
            Token.from_str(token_str)

    token_str = "gt-MLF5MB3Peg79wEC0BY8U8Q.ChbkqEyp3EIJ2e_1Sqff3w"
    token = Token.from_str(token_str)
    assert token.key == "MLF5MB3Peg79wEC0BY8U8Q"
    assert token.secret == "ChbkqEyp3EIJ2e_1Sqff3w"
    assert str(token) == token_str


def test_admin_request() -> None:
    # Invalid token type.
    with pytest.raises(ValidationError):
        AdminTokenRequest(username="someuser", token_type=TokenType.session)

    # User tokens must have a name.
    with pytest.raises(ValidationError):
        AdminTokenRequest(username="someuser", token_type=TokenType.user)

    # Service tokens may not have a name.
    with pytest.raises(ValidationError):
        AdminTokenRequest(
            username="someuser",
            token_type=TokenType.service,
            token_name="some token name",
        )
