"""General utility functions."""

from __future__ import annotations

__all__ = ["add_padding"]


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
