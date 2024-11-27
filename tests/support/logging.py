"""Helper functions for testing logging."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

__all__ = ["parse_log"]


def parse_log(
    caplog: pytest.LogCaptureFixture, *, ignore_debug: bool = False
) -> list[dict[str, Any]]:
    """Parse the accumulated logs as JSON.

    Checks and strips off common log attributes and returns the rest as a list
    of dictionaries holding the parsed JSON of the log message.

    Parameters
    ----------
    caplog
        The log capture fixture.
    ignore_debug
        If set to `True`, filter out all debug messages.

    Returns
    -------
    list of dict
        List of parsed JSON dictionaries with the common log attributes
        removed (after validation).
    """
    now = datetime.now(tz=UTC)
    messages = []

    for log_tuple in caplog.record_tuples:
        message = json.loads(log_tuple[2])
        assert message["logger"] == "gafaelfawr"
        del message["logger"]

        if "timestamp" in message:
            isotimestamp = message["timestamp"]
            assert isotimestamp.endswith("Z")
            timestamp = datetime.fromisoformat(isotimestamp[:-1])
            timestamp = timestamp.replace(tzinfo=UTC)
            assert now - timedelta(seconds=10) < timestamp < now
            del message["timestamp"]

        if "request_id" in message:
            del message["request_id"]
            assert "userAgent" in message["httpRequest"]
            del message["httpRequest"]["userAgent"]

        if not ignore_debug or message["severity"] != "debug":
            messages.append(message)

    return messages
