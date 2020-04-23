########
Overview
########

Gafaelfawr is deployed as an auth subrequest handler for a Kubernetes cluster that uses an nginx ingress.

.. figure:: /_static/architecture.png
   :name: Gafaelfawr deployment architecture

   Gafaelfawr deployment architecture

Gafaelfawr does not talk to the protected application directly or act as a proxy.
Instead, the NGINX ingress makes a subrequest to Gafaelfawr to check the authorization of each request, and may redirect the user to a route served by Gafaelfawr directly for initial authentication, logout, or token maintenance.

Authentication is handled by an external identity provider to which the user will be redirected as necessary.
Gafaelfawr will also make direct requests to that identity provider to get information about the user after authentication.
