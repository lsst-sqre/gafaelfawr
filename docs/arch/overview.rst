########
Overview
########

Gafaelfawr is deployed as an auth subrequest handler for a Kubernetes cluster that uses an NGINX ingress.

.. figure:: /_static/architecture.png
   :name: Gafaelfawr deployment architecture

   Gafaelfawr deployment architecture

In the normal case, Gafaelfawr does not talk to the protected application directly or act as a proxy.
Instead, the NGINX ingress makes a subrequest to Gafaelfawr to check the authorization of each request, and may redirect the user to a route served by Gafaelfawr directly for initial authentication, logout, or token maintenance.

Authentication is handled by an external identity provider to which the user will be redirected as necessary.
Gafaelfawr will also make direct requests to that identity provider to get information about the user after authentication.

For protected applications that only understand OpenID Connect, Gafaelfawr also includes a minimal OpenID Connect server.
This was designed with just enough features to support `Chronograf`_.
It may not work with other applications without additional changes.

.. _Chronograf: https://docs.influxdata.com/chronograf/v1.8/administration/managing-security/

Gafaelfawr can also deploy a Kubernetes ``CronJob`` resource to maintain service tokens in Kubernetes secrets for the use of other applications deployed in the same cluster.
