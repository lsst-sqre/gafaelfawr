"""Setup code for exporting telemetry and traces to Sentry."""

from __future__ import annotations

from typing import Any

import sentry_sdk

__all__ = ["enable_telemetry"]


def enable_telemetry() -> None:
    """Enable sending telemetry and trace information to Sentry.

    This may include secrets and other sensitive data, so currently should
    only be used in a development environment.
    """

    def traces_sampler(context: dict[str, Any]) -> float:
        asgi_scope = context.get("asgi_scope")
        if not asgi_scope:
            return 1
        if asgi_scope.get("path") in ("/", "/health"):
            return 0
        return 1

    # Configuration will be pulled from SENTRY_* environment variables (see
    # https://docs.sentry.io/platforms/python/configuration/options/).  If
    # SENTRY_DSN is not present, telemetry is disabled.
    sentry_sdk.init(enable_tracing=True, traces_sampler=traces_sampler)
