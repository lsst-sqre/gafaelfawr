#############################
Phalanx-provided requirements
#############################

The following requirements are provided by Phalanx_.
Since Phalanx is the only supported deployment mechanism for Gafaelfawr and provides these requirements, normally users won't have to think about them.
If you are modifying Phalanx or if you're trying to use Gafaelfawr outside of the Phalanx environment, however, you should be aware of them.

The `NGINX ingress controller <https://github.com/kubernetes/ingress-nginx>`__ must already be configured and working.
Gafaelfawr only supports that ingress controller.
Gafaelfawr also expects TLS termination to be done by the ingress controller.

Kubernetes 1.19 or later is required to use ``GafaelfawrIngress`` (see :ref:`ingress`), since the generated ingress will use the ``networking.k8s.io/v1`` API introduced in that version.

Gafaelfawr requires Vault_ to store secrets and `Vault Secrets Operator`_ to materialize those secrets as Kubernetes secrets.

.. _client-ips:

Client IP addresses
===================

Gafaelfawr attempts to log the IP address of the client in each log message.
Since Gafaelfawr always expects to be running behind a proxy server, the IP address is taken from the ``X-Forwarded-For`` HTTP header if present.
If that header is not present, the connecting IP address will be used as the IP address of the remote client, but this almost certainly indicates Gafaelfawr has not been deployed correctly.

Making this work properly requires some additional NGINX configuration:

#. Configure the NGINX ingress to generate full, chained ``X-Forwarded-For`` headers.
   Do this by adding the following to the ``ConfigMap`` for the ingress-nginx service:

   .. code-block:: yaml

      data:
        compute-full-forwarded-for: "true"
        use-forwarded-headers: "true"

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

   ingress-nginx:
     controller:
       config:
         compute-full-forwarded-for: "true"
         use-forwarded-headers: "true"
       service:
         externalTrafficPolicy: Local

You may also need to set the ``proxies`` Helm configuration setting to the list of networks used for the NGINX ingress and any other proxies.
See :ref:`helm-proxies` for more details.

Error handling
==============

Gafaelfawr-generated ingresses use a custom location as an ``error_page`` target to pass Gafaelfawr errors back to the client.
This workaround is required because the NGINX ``auth_request`` module can only handle 401 and 403 responses and converts all other failure responses to 500 errors, but Gafaelfawr wants to use other HTTP status codes such as 400.

This custom location must be injected into every NGINX server block so that it is available for Gafaelfawr's use.
This is done by adding a ``server-snippet`` key to the ingress-nginx ``ConfigMap`` using the following setting in the ``values.yaml`` file for ingress-nginx:

.. code-block:: yaml

   ingress-nginx:
     controller:
       config:
         server-snippet: |
           location @autherror {
             add_header Cache-Control "no-cache, must-revalidate" always;
             add_header WWW-Authenticate $auth_www_authenticate always;
             if ($auth_status = 400) {
               add_header Content-Type "application/json" always;
               return 400 $auth_error_body;
             }
             return 403;
           }

This will be added to every server block, not just the ones used by Gafaelfawr-protected services, and therefore may be unused, but this should be harmless.
