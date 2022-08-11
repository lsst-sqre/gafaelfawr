"""Configure logging for Gafaelfawr and uvicorn."""

from __future__ import annotations

import logging.config

import structlog
import uvicorn
from safir.logging import add_log_severity

__all__ = ["setup_uvicorn_logging"]


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
                "json": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processors": processors,
                    "foreign_pre_chain": [
                        add_log_severity,
                        structlog.processors.TimeStamper(fmt="iso"),
                    ],
                },
                **uvicorn.config.LOGGING_CONFIG["formatters"],
            },
            "handlers": {
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
                    "handlers": ["uvicorn.default"],
                    "level": loglevel,
                    "propagate": False,
                },
            },
        }
    )
