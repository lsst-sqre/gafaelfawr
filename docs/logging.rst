#######
Logging
#######

Gafaelfawr uses structlog_ (via Safir_) to log all its internal messages in JSON.
It is run via uvicorn_, which also logs all requests in the standard Apache log format.
Interesting events that are not obvious from the access logging done by uvicorn are logged at the ``INFO`` level.
User errors are logged at the ``WARNING`` level.
Gafaelfawr or other identity management errors are logged at the ``ERROR`` level.

.. _Safir: https://safir.lsst.io/
.. _structlog: https://www.structlog.org/en/stable/
.. _uvicorn: https://www.uvicorn.org/

Log attributes
==============

The main log message will be in the ``event`` attribute of each log message.
If this message indicates an error with supplemental information, the additional details of the error will be in the ``error`` attribute.

Gafaelfawr will add some consistent attributes to log messages, in addition to the default attributes `added by Safir <https://safir.lsst.io/logging.html>`__.
All authenticated routes add the following attributes once the user's token has been located and verified:

``scope``
    The scopes of the authentication token.

``token``
    The key of the authentication token.

``token_source``
    Where the token was found.
    Chosen from ``cookie`` (found in the session cookie), ``bearer`` (provided as a bearer token in an ``Authorization`` header), or ``basic-username`` or ``basic-password`` (provided as the username or password in an HTTP Basic ``Authorization`` header).

``user``
    The username of the token.

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

Some actions will add additional structured data appropriate to that action.

.. _client-ips:

Client IP addresses
===================

Gafaelfawr attempts to determine the IP address of the client to log as the ``remote`` log attribute.
(It does not attempt to log the client hostname.)
Since Gafaelfawr always expects to be running behind a proxy server, the IP address is taken from the ``X-Forwarded-For`` HTTP header if present.
(If not present, the connecting IP address will be used as the IP address of the remote client, but this almost certainly indicates Gafaelfawr has not been deployed correclty.)

Making this work properly requires some additional configuration:

#. Set the ``proxies`` configuration setting to the list of networks used for the NGINX ingress and any other proxies.
   See :ref:`helm-proxies`.

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

If you are using the `ingress-nginx Helm chart <https://github.com/kubernetes/ingress-nginx/tree/main/charts/ingress-nginx>`__, you can make both of the required NGINX ingress changes with the following ``values.yaml`` file:

.. code-block:: yaml

   nginx-ingress:
     controller:
       config:
         compute-full-forwarded-for: "true"
         use-forwarded-headers: "true"
       service:
         externalTrafficPolicy: Local

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
