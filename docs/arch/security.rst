##############
Security model
##############

Threat model
============

Gafaelfawr provides an authentication and authorization gate for Kubernetes services using the NGINX ingress.
It attempts to provide the following security services:

- Incoming web requests will not be allowed through to the protected service unless they present a valid token.
- Unauthenticated browser users will be sent to a configured authentication provider and then returned to the service they are attempting to access.
- Tokens expire at a configurable interval, forcing reauthentication, with the exception of user tokens, which can be created without an expiration.
- Users may create (and delete) new tokens for use outside the browser, but their scopes are limited to the scopes of their own token.
- Tokens to act on behalf of the user are only issued to protected applications on request, are marked with the application to which they were issued, and can be restricted in scope.

In providing those services, it attempts to maintain the following properties:

- Authentication cookies are tamper-resistent, protected by a key held by Gafaelfawr.
  (However, they are bearer cookies and can be copied and reused.)
- Tokens provided to protected applications are opaque and must be validated by Gafaelfawr on use.
- Gafaelfawr itself is hardened against common web security attacks, specifically session fixation on initial authentication, CSRF on token creation and deletion, cookie theft, and open redirects from the login and logout handlers.
- Access to the underlying Gafaelfawr storage does not allow the attacker to bypass Gafaelfawr's authentication checks.
  The contents of the storage are protected by a key held by Gafaelfawr.

Gafaelfawr does not attempt to protect against the following threats:

- Web security vulnerabilities in the protected application.
  Gafaelfawr only provides authentication gating.
  After authorization, the web request and response from the protected application are not modified and no additional security properties are added.
- Compromise of the internal Kubernetes network.
  Gafaelfawr does not support TLS or other security measures inside the Kubernetes network.
  It assumes internal Kubernetes network traffic cannot be intercepted or tampered with.
- Cookie or token theft.
  Gafaelfawr relies on the security of the browser cookie cache and the security properties of HTTP cookies to protect its session cookie from theft.
  An attacker who is able to steal the cookie is able to impersonate the user from whom they stole the cookie.
  Similarly, Gafaelfawr issues bearer tokens on user request, and those tokens are sufficient for authentication.
  Gafaelfawr does not protect against token mishandling or theft.
- Compromise of Gafaelfawr's secrets.
  If an attacker gains access to the Kubernetes secrets or the Gafaelfawr pod, that attacker will be able to impersonate any user.
- Manipulation of the Redis store.
  Gafaelfawr assumes the Redis store does not require authentication.
  An attacker with access to the Kubernetes network likely will be able to gain access to anything in Redis.
  The important information is encrypted and integrity-protected, but an attacker with Redis access could trivially cause a denial of service by deleting user sessions.

Future work
===========

- A protected application receives the user's cookies and thus the Gafaelfawr cookie.
  It could then use that cookie to impersonate the user to other protected applications or to Gafaelfawr itself.
  Fixing this will likely require moving each application to its own domain and using a more complex cookie scheme where each domain's cookies is valid only for requests to that domain.
  The credentials to authenticate to Gafaelfawr itself would then only be available to the Gafaelfawr domain, which should be distinct from any protected application's domain.
- Register the ``redirect_uri`` along with the client for OpenID Connect clients and validate that the requested ``redirect_uri`` matches.
  This would allow using the OpenID Connect support to authenticate sites on other hosts, including chaining Gafaelfawr instances, since it would allow safely removing the restriction that ``redirect_uri`` must be on the same host as Gafaelfawr.


Mitigation details
==================

Gafaelfawr uses four secure storage artifacts:

- A token.
  A token has two components: the key and a secret.
  The key is visible to anyone who can list the keys in the Gafaelfawr Redis store or authenticate to the token API as the user.
  Security of the system does not rely on keeping the key confidential.
  Proof of possession comes from the secret portion of the session handle, which must match the secret value stored inside the encrypted session for the session handle to be valid.
  The secret is a 128-bit random value generated using :py:func:`os.urandom`.
- A session cookie.
  Gafaelfawr uses an encrypted cookie to store the token for a browser authentication session, as well as other security-sensitive secrets (the CSRF token, the random state for OAuth 2.0 or OpenID Connect authentication).
  This cookie is encrypted using `~cryptography.fernet.Fernet`.
- Redis session store.
  Sessions stored in Redis, which include the secret value used to verify the token for the user, are encrypted using `~cryptography.fernet.Fernet`.
  The key used is the same key used for encrypting the session cookie.
- SQL data store.
  Metadata about tokens, users with administrative access to the token API, and event history are stored in a SQL database.
  The token secrets and the user information associated with a token are not stored in the database and cannot be reconstructed from the database.
  The SQL data store is protected via the normal authentication credentials of a SQL database connection (generally a password).
- A JWT, for protected applications using OpenID Connect.
  The contents are readable by anyone but the integrity is protected by a public key signature.
  Gafaelfawr uses the ``RS256`` algorithm, which uses a 2048-bit RSA key.
  JWT signing and validation is done using the `PyJWT <https://pyjwt.readthedocs.io/en/latest/>`__ library.

During initial authentication, Gafaelfawr sends a ``state`` parameter to the OAuth 2.0 or OpenID Connect authentication provider and also stores that parameter in the session cookie.
On return from authentication, the ``state`` parameter returned by the authentication provider is compared to the value in the session cookie and the authentication is rejected if they do not match.
This protects against session fixation (an attacker tricking a user into authenticating as the attacker instead of the user, thus giving the attacker access to data subsequently uploaded to the user).
The state value is a 128-bit random value generated using :py:func:`os.urandom`.

CSRF tokens are generated on request via the ``/auth/api/v1/login`` route and stored in the session cookie.
On POST, PATCH, PUT, and DELETE API requests authenticated with a session cookie, the CSRF token must be provided in the ``X-CSRF-Token`` headere and must match the CSRF token in the session cookie.
API requests authenticated via an ``Authorization`` header need not provide a CSRF token, since browsers cannot be tried into generating such requests with existing credentials.

The ``/login`` and ``/logout`` routes redirect the user after processing.
The URL to which to redirect the user may be specified as a GET parameter or, in the case of ``/login``, an HTTP header that is normally set by the NGINX ingress.
To protect against open redirects, the specified redirect URL must be on the same host as the host portion of the incoming request for the ``/login`` or ``/logout`` route.
``X-Forwarded-Host`` headers (expected to be set by the NGINX ingress) are trusted for the purposes of determining the host portion of the request.

``Forwarded`` appears not to be supported by the NGINX ingress at present and therefore is not used.

Logging
=======

Every request to Gafaelfawr is logged via uvicorn access logs.
Interesting actions are also logged directly in Gafaelfawr in JSON format and include as many details about the request as seemed useful.
They include, in the ``remote`` data item, the client IP address.
This is determined from ``X-Forwarded-For`` headers, which are expected to be set by the NGINX ingress and are trusted by Gafaelfawr for logging purposes.
See :ref:`client-ips` for more information.
