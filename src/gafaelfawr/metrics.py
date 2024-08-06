"""Metrics implementation for Gafaelfawr."""

from __future__ import annotations

from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    MetricReader,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from pydantic import AnyHttpUrl

__all__ = [
    "FrontendMetrics",
    "GafaelfawrMetrics",
    "StateMetrics",
]


class GafaelfawrMetrics:
    """Base class for OpenTelemetry instruments for Gafaelfawr.

    Gafaelfawr has several different containers of metrics instruments used by
    its different components. This base class contains the shared code common
    to all of them, such as initializing the metrics exporter. Only one
    subclass of this class should be instantiated in a given process. (This is
    not enforced.)

    Parameters
    ----------
    url
        URL to the OpenTelemetry collector to which to send metrics.
    meter_name
        Name of the meter, which should correspond to the component of
        Gafaelfawr that logs these metrics.
    metric_reader
        If provided, do not collect and send metrics to the OpenTelemetry
        collector, and instead use the provided metric reader. This is used by
        the test suite to disable the OpenTelemetry exporter in favor of an
        in-memory metrics reader that can be queried by the test suite.

    Attributes
    ----------
    meter
        Meter that should be used to create instruments.
    """

    def __init__(
        self,
        url: AnyHttpUrl | str,
        meter_name: str,
        metric_reader: MetricReader | None = None,
    ) -> None:
        resource = Resource(attributes={SERVICE_NAME: "gafaelfawr"})
        if not metric_reader:
            exporter = OTLPMetricExporter(str(url), insecure=True)
            metric_reader = PeriodicExportingMetricReader(exporter)
        provider = MeterProvider([metric_reader], resource)
        self.meter = provider.get_meter(meter_name)


class FrontendMetrics(GafaelfawrMetrics):
    """Metric instruments for the Gafaelfawr frontend.

    Parameters
    ----------
    url
        URL to the OpenTelemetry collector to which to send metrics.
    metric_reader
        If provided, do not collect and send metrics to the OpenTelemetry
        collector, and instead use the provided metric reader. This is used by
        the test suite to disable the OpenTelemetry exporter in favor of an
        in-memory metrics reader that can be queried by the test suite.

    Attributes
    ----------
    login_attempts
        Count of times Gafaelfawr sends the user to the identity provider for
        authentication. This does not include duplicate redirects when the
        given user already has an authentication in progress.
    login_enrollment
        Count of the number of Gafaelfawr redirects an authenticated but
        unknown user to the enrollment flow.
    login_failures
        Count of the times a login fails at the Gafaelfawr end, meaning that
        either something went wrong in Gafaelfawr itself, with the request to
        the remote authentication service, or via an error reported by the
        remote authentication service. This does not count cases where the
        authentication service never returns the user to us.
    login_success_time
        How long it takes for the user to go through the login process. The
        authenticated username must be included as the ``username`` attribute.
    login_successes
        Count of times the user returns successfully from the identity
        provider after authenticating. The authenticated username must be
        included as the ``username`` attribute.
    request_auth
        An authenticated request to a service. Currently this is only logged
        when a token is delegated to the service due to limitations in the
        Gafaelfawr design. The authenticated username must be included as the
        ``username`` attribute and the service name must be included as the
        ``service`` attribute.
    """

    def __init__(
        self, url: AnyHttpUrl | str, metric_reader: MetricReader | None = None
    ) -> None:
        super().__init__(url, "frontend", metric_reader)
        self.login_attempts = self.meter.create_counter(
            "login.attempts",
            unit="1",
            description=(
                "Count of times Gafaelfawr sends the user to the identity"
                " provider to authenticate, not including duplicate redirects"
                " when the given user already has an authentication in"
                " progress."
            ),
        )
        self.login_enrollment = self.meter.create_counter(
            "login.enrollment",
            unit="1",
            description=(
                "Count of times Gafaelfawr redirects a user to the enrollment"
                " flow."
            ),
        )
        self.login_failures = self.meter.create_counter(
            "login.failures",
            unit="1",
            description=(
                "Count of the times a login fails at the Gafaelfawr end,"
                " meaning that either something went wrong in Gafaelfawr"
                " itself, with the request to the remote authentication"
                " service, or via an error reported by the remote"
                " authentication service. This does not count cases where"
                " the authentication service never returns the user to us."
            ),
        )
        self.login_success_time = self.meter.create_gauge(
            "login.success_time",
            unit="s",
            description=(
                "How long it takes for the user to go through the login"
                " process. The authenticated username is included as an"
                " attribute."
            ),
        )
        self.login_successes = self.meter.create_counter(
            "login.successes",
            unit="1",
            description=(
                "Count of times the user returns successfully from the"
                " identity provider after authenticating. The authenticated"
                " username is included as an attribute."
            ),
        )
        self.request_auth = self.meter.create_counter(
            "request.auth",
            unit="1",
            description=(
                "An authenticated request to an underlying service. Currently"
                " this is only logged for requests that delegate an internal"
                " token to the service, since those are the only ones for"
                " which Gafaelfawr knows the service name. Attributes are the"
                " service name and the authenticated username."
            ),
        )


class StateMetrics(GafaelfawrMetrics):
    """Metric instruments based on stored state.

    Collects metrics determined from the current stored state. These are
    gathered and reported by the maintenance cron job.

    Parameters
    ----------
    url
        URL to the OpenTelemetry collector to which to send metrics.
    metric_reader
        If provided, do not collect and send metrics to the OpenTelemetry
        collector, and instead use the provided metric reader. This is used by
        the test suite to disable the OpenTelemetry exporter in favor of an
        in-memory metrics reader that can be queried by the test suite.

    Attributes
    ----------
    sessions_active_users
        Total number of unexpired user sessions (unexpired session tokens).
    user_tokens_active
        Total number of unexpired user tokens.
    """

    def __init__(
        self, url: AnyHttpUrl | str, metric_reader: MetricReader | None = None
    ) -> None:
        super().__init__(url, "state", metric_reader)
        self.sessions_active_users = self.meter.create_gauge(
            "sessions.active_users",
            unit="1",
            description="Number of users with unexpired user sessions",
        )
        self.user_tokens_active = self.meter.create_gauge(
            "user_tokens.active",
            unit="1",
            description="Number of unexpired user tokens",
        )
