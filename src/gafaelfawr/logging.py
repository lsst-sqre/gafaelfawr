"""Configure logging for Gafaelfawr and uvicorn."""

from __future__ import annotations

import logging
import logging.config
import re

import structlog
import uvicorn
from safir.logging import add_log_severity
from structlog.types import EventDict

ACCESS_LOG_REGEX = re.compile(r'^([0-9.]+):([0-9]+) - "([^"]+)" ([0-9]+)$')

__all__ = ["setup_uvicorn_logging"]


def process_uvicorn_access_log(
    logger: logging.Logger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Parse a uvicorn access log entry into key/value pairs.

    Intended for use as a structlog processor.

    This checks whether the log message is a uvicorn access log entry and, if
    so, parses the message into key/value pairs for JSON logging so that the
    details can be programmatically extracted.  ``remoteIp`` is intentionally
    omitted since it isn't aware of ``X-Forwarded-For`` and will therefore
    always point to an uninteresting in-cluster IP.

    Parameters
    ----------
    logger : `logging.Logger`
        The wrapped logger object.
    method_name : `str`
        The name of the wrapped method (``warning`` or ``error``, for
        example).
    event_dict : `structlog.types.EventDict`
        Current context and current event. This parameter is also modified in
        place, matching the normal behavior of structlog processors.

    Returns
    -------
    event_dict : `structlog.types.EventDict`
        The modified `~structlog.types.EventDict` with the added key.
    """
    match = ACCESS_LOG_REGEX.match(event_dict["event"])
    if not match:
        return event_dict
    request = match.group(3)
    method, rest = request.split(" ", 1)
    url, protocol = rest.rsplit(" ", 1)
    if "httpRequest" not in event_dict:
        event_dict["httpRequest"] = {}
    event_dict["httpRequest"]["protocol"] = protocol
    event_dict["httpRequest"]["requestMethod"] = method
    event_dict["httpRequest"]["requestUrl"] = url
    event_dict["httpRequest"]["status"] = match.group(4)
    return event_dict


def setup_uvicorn_logging(loglevel: str = "INFO") -> None:
    """Set up logging.

    This configures the uvicorn to use structlog for output formatting.  It is
    used by the main FastAPI application.

    Parameters
    ----------
    loglevel : `str`
        Log level for uvicorn logging.  Default is ``INFO``.
    """
    processors = [
        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
        structlog.processors.JSONRenderer(),
    ]
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "json-access": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processors": processors,
                    "foreign_pre_chain": [
                        add_log_severity,
                        process_uvicorn_access_log,
                    ],
                },
                "json": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processors": processors,
                    "foreign_pre_chain": [add_log_severity],
                },
                **uvicorn.config.LOGGING_CONFIG["formatters"],
            },
            "handlers": {
                "uvicorn.access": {
                    "level": loglevel,
                    "class": "logging.StreamHandler",
                    "formatter": "json-access",
                },
                "uvicorn.default": {
                    "level": loglevel,
                    "class": "logging.StreamHandler",
                    "formatter": "json",
                },
            },
            "loggers": {
                "uvicorn.error": {
                    "handlers": ["uvicorn.default"],
                    "level": loglevel,
                    "propagate": False,
                },
                "uvicorn.access": {
                    "handlers": ["uvicorn.access"],
                    "level": loglevel,
                    "propagate": False,
                },
            },
        }
    )
