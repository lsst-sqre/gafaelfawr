"""Utility functions for tests."""

from datetime import UTC, datetime, timedelta


def assert_is_now(date: datetime) -> None:
    """Assert that a datetime is reasonably close to the current time.

    Parameters
    ----------
    date
        Datetime to check.
    """
    now = datetime.now(tz=UTC).replace(microsecond=0)
    assert now - timedelta(seconds=5) <= date <= now
