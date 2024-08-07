"""Metrics implementation for Gafaelfawr."""

from __future__ import annotations

import os

from opentelemetry import metrics
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    ConsoleMetricExporter,
    MetricExporter,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.resources import SERVICE_NAME, Resource

__all__ = ["instruments"]


class Instruments:
    """OpenTelemetry instruments used to log Gafaelfawr metrics."""

    def __init__(self) -> None:
        resource = Resource(attributes={SERVICE_NAME: "gafaelfawr"})
        if os.getenv("GAFAELFAWR_TESTING"):
            exporter: MetricExporter = ConsoleMetricExporter()
        else:
            exporter = OTLPMetricExporter(
                "http://telegraf.telegraf:4317", insecure=True
            )
        reader = PeriodicExportingMetricReader(exporter)
        provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(provider)
        meter = metrics.get_meter("gafaelfawr.frontend")
        self.login_attempts = meter.create_counter(
            "login.attempts",
            unit="1",
            description=(
                "Count of times Gafaelfawr sends the user to the identity"
                " provider to authenticate"
            ),
        )
        self.login_successes = meter.create_counter(
            "login.successes",
            unit="1",
            description=(
                "Count of times the user returns successfully from the"
                " identity provider after authenticating"
            ),
        )


instruments = Instruments()
"""Global metrics instruments for Gafaelfawr."""
