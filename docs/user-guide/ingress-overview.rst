.. _ingress-overview:

#######################################
How Gafaelfawr-protected ingresses work
#######################################

Gafaelfawr is introduced into the HTTP request path for your services as an NGINX ``auth_request`` subhandler.
This is done via annotations added to the Kubernetes ``Ingress`` resource that are interpreted by ingress-nginx_.

For each HTTP request to a protected service, NGINX will send a request to the Gafaelfawr ``/auth`` route with the headers of the incoming request (including, for example, any cookies or ``Authorization`` header).
Gafaelfawr, when receiving that request, will find the user's authentication token, check that it is valid, and check that the user has the required scope.

If the user is not authenticated, it will either return a 401 error with an appropriate ``WWW-Authenticate`` challenge, or a redirect to the sign-in URL, depending on Gafaelfawr's configuration.
The sign-in URL would then send the user to CILogon, an OpenID Connect server, or GitHub to authenticate.

If the user is already authenticated but does not have the desired scope, Gafaelfawr will return a 403 error, which will be passed back to the user.

If the user is authenticated and authorized, Gafaelfawr will return a 200 response with some additional headers containing information about the user and (optionally) a delegated token.
NGINX will then send the user's HTTP request along to the protected service, including those headers in the request.
