"""Utility functions for tests."""

from datetime import datetime, timedelta

from safir.datetime import current_datetime


def assert_is_now(date: datetime) -> None:
    """Assert that a datetime is reasonably close to the current time.

    Parameters
    ----------
    date
        Datetime to check.
    """
    now = current_datetime()
    assert now - timedelta(seconds=5) <= date <= now
