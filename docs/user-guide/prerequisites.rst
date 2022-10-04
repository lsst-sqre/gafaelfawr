#############
Prerequisites
#############

The `NGINX ingress controller <https://github.com/kubernetes/ingress-nginx>`__ must already be configured and working.
Gafaelfawr only supports that ingress controller.
Gafaelfawr also expects TLS termination to be done by the ingress controller.

Some additional NGINX configuration is required for accurate logging of client IPs.
See :ref:`Logging client IP addresses <client-ips>` for more information.

A PostgreSQL database is required but not provided by the Helm chart.
You must provision this database and configure it as described below.
Google Cloud SQL (including the Google Cloud SQL Auth Proxy) is supported (and preferred).

Redis is also required for storage, but the Gafaelfawr Helm chart will configure and deploy a private Redis server for this purpose.
However, you will need to configure persistent storage for that Redis server for any non-test deployment, which means that the Kubernetes cluster must provide persistent storage.

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

   nginx-ingress:
     controller:
       config:
         compute-full-forwarded-for: "true"
         use-forwarded-headers: "true"
       service:
         externalTrafficPolicy: Local

You may also need to set the ``proxies`` Helm configuration setting to the list of networks used for the NGINX ingress and any other proxies.
See :ref:`helm-proxies` for more details.
