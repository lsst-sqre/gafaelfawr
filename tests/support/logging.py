"""Helper functions for testing logging."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Dict, List

    from _pytest.logging import LogCaptureFixture


def parse_log(caplog: LogCaptureFixture) -> List[Dict[str, Any]]:
    """Parse the accumulated logs as JSON.

    Checks and strips off common log attributes and returns the rest as a list
    of dictionaries holding the parsed JSON of the log message.

    Parameters
    ----------
    caplog : `_pytest.logging.LogCaptureFixture`
        The log capture fixture.

    Returns
    -------
    messages : List[Dict[`str`, Any]]
        List of parsed JSON dictionaries with the common log attributes
        removed (after validation).
    """
    now = datetime.now(tz=timezone.utc)
    messages = []

    for log_tuple in caplog.record_tuples:
        message = json.loads(log_tuple[2])
        assert message["logger"] == "gafaelfawr"
        del message["logger"]

        isotimestamp = message["timestamp"]
        assert isotimestamp.endswith("Z")
        timestamp = datetime.fromisoformat(isotimestamp[:-1])
        timestamp = timestamp.replace(tzinfo=timezone.utc)
        assert now - timedelta(seconds=10) < timestamp < now
        del message["timestamp"]

        if "request_id" in message:
            del message["request_id"]
            assert "userAgent" in message["httpRequest"]
            del message["httpRequest"]["userAgent"]

        messages.append(message)

    return messages
