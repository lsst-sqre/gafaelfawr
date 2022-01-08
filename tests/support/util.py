"""Utility functions for tests."""

from __future__ import annotations

from datetime import datetime, timedelta

from gafaelfawr.util import current_datetime


def assert_is_now(date: datetime) -> None:
    """Assert that a datetime is reasonably close to the current time."""
    now = current_datetime()
    assert now - timedelta(seconds=5) <= date <= now
