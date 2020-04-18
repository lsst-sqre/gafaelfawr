"""General utility functions."""

from __future__ import annotations

import base64

__all__ = ["add_padding", "base64_to_number"]


def add_padding(encoded: str) -> str:
    """Add padding to base64 encoded bytes.

    Parameters
    ----------
    encoded : `str`
        A base64-encoded string, possibly with the padding removed.

    Returns
    -------
    result : `str`
        A correctly-padded version of the encoded string.
    """
    underflow = len(encoded) % 4
    if underflow:
        return encoded + ("=" * (4 - underflow))
    else:
        return encoded


def base64_to_number(data: str) -> int:
    """Convert base64-encoded bytes to an integer.

    Parameters
    ----------
    data : `str`
        Base64-encoded number, possibly without padding.

    Returns
    -------
    result : `int`
        The result converted to a number.  Note that Python ints can be
        arbitrarily large.

    Notes
    -----
    Used for converting the modulus and exponent in a JWKS to integers in
    preparation for turning them into a public key.
    """
    decoded = base64.urlsafe_b64decode(add_padding(data))
    return int.from_bytes(decoded, byteorder="big")


def number_to_base64(data: int) -> bytes:
    """Convert an integer to base64-encoded bytes in big endian order.

    Parameters
    ----------
    data : `int`
        Arbitrarily large number

    Returns
    -------
    result : `bytes`
        The equivalent URL-safe base64-encoded string corresponding to the
        number in big endian order.
    """
    bit_length = data.bit_length()
    byte_length = bit_length // 8 + 1
    data_as_bytes = data.to_bytes(byte_length, byteorder="big", signed=False)
    return base64.urlsafe_b64encode(data_as_bytes)
