"""Tests for the jwt_authorizer.tokens package."""

from __future__ import annotations

from jwt_authorizer.util import add_padding, base64_to_number, number_to_base64
from tests.util import RSAKeyPair


def test_add_padding() -> None:
    assert add_padding("") == ""
    assert add_padding("Zg") == "Zg=="
    assert add_padding("Zgo") == "Zgo="
    assert add_padding("Zm8K") == "Zm8K"
    assert add_padding("Zm9vCg") == "Zm9vCg=="


def test_base64_to_number() -> None:
    keypair = RSAKeyPair()
    for n in (
        0,
        1,
        65535,
        65536,
        2147483648,
        4294967296,
        18446744073709551616,
        keypair.public_numbers().e,
        keypair.public_numbers().n,
    ):
        n_b64 = number_to_base64(n).decode().rstrip("=")
        assert base64_to_number(n_b64) == n

    assert base64_to_number("AQAB") == 65537


def test_number_to_base64() -> None:
    assert number_to_base64(0) == b"AA=="
    assert number_to_base64(65537) == b"AQAB"
