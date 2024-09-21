#######
Logging
#######

Gafaelfawr uses structlog_ to log all messages.
All log messages are in JSON to allow for easier analysis and searching using log exploration frameworks such as Google Cloud Logging.
This unfortunately comes at a cost of making them somewhat harder to read in plain text form.

The uvicorn_ logging configuration is overridden to convert those log messages to JSON as well.

Client IP addresses
===================

Gafaelfawr tries to include the real client IP of the request in each message about a client request.
This poses some challenges because Gafaelfawr is running as a subrequest handler behind a proxy.

Determining the client IP from ``X-Forwarded-For`` is complicated because Gafaelfawr's ``/ingress/auth`` route is called via an NGINX ``auth_request`` directive.
In the Kubernetes NGINX ingress, this involves three layers of configuration.
The protected service will have an ``auth_request`` directive that points to a generated internal location.
That internal location will set ``X-Forwarded-For`` and then proxy to the ``/ingress/auth`` route.
The ``/ingress/auth`` route configuration is itself a proxy that also sets ``X-Forwarded-For`` and then proxies the request to Gafaelfawr.
Because of this three-layer configuration, if NGINX is configured to always replace the ``X-Forwarded-For`` header, Gafaelfawr will receive a header containing only the IP address of the NGINX ingress.

The configuration described in :ref:`client-ips` tells the NGINX ingress to instead retain the original ``X-Forwarded-For`` and append each subsequent client IP.
The ``proxies`` configuration (:ref:`helm-proxies`) then tells Gafaelfawr which entries in that list to ignore when walking backwards to find the true client IP.

Unfortunately, this still doesn't work if Kubernetes replaces the original client IP using source NAT before the NGINX ingress ever sees it.
Therefore, source NAT also has to be disabled for inbound connections to the NGINX ingress.
That's done with the ``externalTrafficPolicy`` setting described in :ref:`client-ips`
