"""Tests for the gafaelfawr.session package."""

from __future__ import annotations

import pytest

from gafaelfawr.session import InvalidSessionHandleException, SessionHandle


def test_handle() -> None:
    handle = SessionHandle()
    assert handle.encode().startswith("gsh:")


def test_handle_from_str() -> None:
    bad_handles = [
        "",
        ".",
        "MLF5MB3Peg79wEC0BY8U8Q",
        "MLF5MB3Peg79wEC0BY8U8Q.",
        "gsh:",
        "gsh:.",
        "gsh:MLF5MB3Peg79wEC0BY8U8Q",
        "gsh:MLF5MB3Peg79wEC0BY8U8Q.",
        "gsh:.ChbkqEyp3EIJ2e_1Sqff3w",
        "gsh:NOT.VALID",
        "gsh:MLF5MB3Peg79wEC0BY8U8Q.ChbkqEyp3EIJ2e_1Sqff3w.!!!!",
        "gshMLF5MB3Peg79wEC0BY8U8Q.ChbkqEyp3EIJ2e_1Sqff3w",
    ]
    for handle_str in bad_handles:
        with pytest.raises(InvalidSessionHandleException):
            SessionHandle.from_str(handle_str)

    handle_str = "gsh:MLF5MB3Peg79wEC0BY8U8Q.ChbkqEyp3EIJ2e_1Sqff3w"
    handle = SessionHandle.from_str(handle_str)
    assert handle.key == "MLF5MB3Peg79wEC0BY8U8Q"
    assert handle.secret == "ChbkqEyp3EIJ2e_1Sqff3w"
    assert handle.encode() == handle_str
