"""General utility functions."""

from __future__ import annotations

from typing import TYPE_CHECKING

import redis

if TYPE_CHECKING:
    from flask import Flask

__all__ = ["add_padding", "get_redis_client"]


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


def get_redis_client(app: Flask) -> redis.Redis:
    """Get a Redis client from the Flask application pool.

    Exists primarily to be overridden by tests.

    Parameters
    ----------
    app : `flask.Flask`
        The Flask application.

    Returns
    -------
    redis_client : `redis.Redis`
        A Redis client.
    """
    return redis.Redis(connection_pool=app.redis_pool)
