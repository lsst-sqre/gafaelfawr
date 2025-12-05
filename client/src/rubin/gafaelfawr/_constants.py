"""Constants for the Gafaelfawr client."""

from __future__ import annotations

from datetime import timedelta

__all__ = ["CACHE_LIFETIME", "CACHE_SIZE"]

CACHE_LIFETIME = timedelta(minutes=5)
"""How long to cache user information retrieved from Gafaelfawr.

Gafaelfawr policy says that this should not be any longer than five minutes so
that changes to the user's groups are picked up correctly.
"""

CACHE_SIZE = 1000
"""Maximum number of users whose information is cached in memory."""
