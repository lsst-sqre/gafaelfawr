#######
Logging
#######

Gafaelfawr uses structlog to log all messages in JSON.
Most routes will log a single message at the ``INFO`` log level (the default) on success.
The ``/login`` route does a bit more work and will log more messages.
More detailed logging is available at the ``DEBUG`` level, including a snapshot of Gafaelfawr's configuration on initial startup.
User errors are logged at the ``WARNING`` level.

Log attributes
==============

The main log message will be in the ``event`` attribute of each log message.
If this message indicates an error with supplemental information, the additional details of the error will be in the ``error`` attribute.

The following attributes will be added to each log message, in addition to the default attributes added by :py:mod:`structlog`:

``logger``
    Always set to ``gafaelfawr``.

``method``
    The HTTP method of the request.

``path``
    The path portion of the HTTP request.

``remote``
    The remote IP address making the request.
    This will be taken from ``X-Forwarded-For`` if available, since Gafaelfawr is designed to be run behind a Kubernetes NGINX ingress.
    See :ref:`client-ips` for more details.

``request_id``
    A unique UUID for each request.
    This can be used to correlate multiple messages logged from a single request.

``user_agent``
    The ``User-Agent`` header of the incoming request.
    This can be helpful in finding requests from a particular user or investigating problems with specific web browsers.

All authenticated routes add the following attributes once the user's token has been located and verified:

``scope``
    The ``scope`` claim of the user's token.

``token``
    The ``jti`` claim of the token.

``user``
    The username claim of the token (configured via the ``username_claim`` configuration parameter).

The ``/auth`` route adds the following attributes:

``auth_uri``
    The URL being authenticated.
    This is the URL (withough the scheme and host) of the original request that Gafaelfawr is being asked to authenticate via a subrequest.
    This will be ``NONE`` if the request was made directly to the ``/auth`` endpoint (which should not happen in normal usage, but may happen during testing).

``required_scope``
    The list of scopes required, taken from the ``scope`` query parameter

``satisfy``
    The authorization strategy, taken from the ``satisfy`` query parameter.

The ``/login`` route adds the following attributes:

``return_url``
    The URL to which the user will be sent after successful authentication.

.. _client-ips:

Client IP addresses
===================

Gafaelfawr attempts to determine the IP address of the client to log as the ``remote`` log attribute.
Since Gafaelfawr always expects to be running behind a proxy server, the IP address is taken from the ``X-Forwarded-For`` HTTP header if present.
(If not present, the connecting IP address will be used as the IP address of the remote client, but this almost certainly indicates Gafaelfawr has not been deployed correclty.)

Making this work properly requires some additional configuration:

#. Set the ``proxies`` configuration setting to the list of networks used for the NGINX ingress and any other proxies.
   See :ref:`settings`.

#. Configure the NGINX ingress to generate full, chained ``X-Forwarded-For`` headers.
   Do this by adding:

   .. code-block:: yaml

      data:
        compute-full-forwarded-for: "true"
        use-forwarded-headers: "true"

   to the ``ConfigMap`` for the NGINX ingress.
   See the `NGINX Ingress Controller documentation <https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/>`__ for more details.
   Be aware that this will affect every service behind the NGINX ingress, not just Gafaelfawr, so all other services must be prepared for receiving a full ``X-Forwaded-For`` header, possibly including (on the left-most end) addresses sent by a malicious client.
   There is more information at `the Wikipedia article on X-Forwarded-For <https://en.wikipedia.org/wiki/X-Forwarded-For>`__.

   This workaround would no longer be needed if `this feature request for the NGINX ingress were implemented <https://github.com/kubernetes/ingress-nginx/issues/5547>`__.

#. Disable Kubernetes source IP NAT for the NGINX ingress.
   This is required on GKE and may be required on other Kubernetes environments.
   Do this by adding ``spec.externalTrafficPolicy`` to ``Local`` in the ``Service`` resource definition for the NGINX ingress controller.
   This comes with some caveats and drawbacks.
   See `this Medium post <https://medium.com/pablo-perez/k8s-externaltrafficpolicy-local-or-cluster-40b259a19404>`__ for more details.

For the curious, here are the details of why these changes are required.

Determining the client IP from ``X-Forwarded-For`` is complicated because Gafaelfawr's ``/auth`` route is called via an NGINX ``auth_request`` directive.
In the Kubernetes NGINX ingress, this involves three layers of configuration.
The protected service will have an ``auth_request`` directive that points to a generated internal location.
That internal location will set ``X-Forwarded-For`` and then proxy to the ``/auth`` route.
The ``/auth`` route configuration is itself a proxy that also sets ``X-Forwarded-For`` and then proxies the request to Gafaelfawr.
Because of this three-layer configuration, if NGINX is configured to always replace the ``X-Forwarded-For`` header, Gafaelfawr will receive a header containing only the IP address of the NGINX ingress.

The above configuration tells the NGINX ingress to instead retain the original ``X-Forwarded-For`` and append each subsequent client IP.
The ``proxies`` configuration then tells Gafaelfawr which entries in that list to ignore when walking backwards to find the true client IP.

Unfortunately, this still doesn't work if Kubernetes replaces the original client IP using source NAT before the NGINX ingress ever sees it.
Therefore, source NAT also has to be disabled for inbound connections to the NGINX ingress.
That's done with the ``externalTrafficPolicy`` setting described above.
