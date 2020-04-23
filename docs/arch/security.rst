##############
Security model
##############

Threat model
============

Gafaelfawr provides an authentication and authorization gate for Kubernetes services using the nginx ingress.
It attempts to provide the following security services:

- Incoming web requests will not be allowed through to the protected service unless they present a valid token or session handle.
- Unauthenticated browser users will be sent to a configured authentication provider and then returned to the service they are attempting to access.
- Tokens and session handles expire at a configurable interval, forcing reauthentication.
- Users may create (and delete) new session handles for use outside the browser, but their scopes are limited to the scopes of their own token or session handle.

In providing those services, it attempts to maintain the following properties:

- Authentication cookies are tamper-resistent, protected by a key held by Gafaelfawr.
- Tokens provided to protected applications are properly signed by a key held by Gafaelfawr and can be independently verified by the protected application.
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
- Reuse of the JWT by a protected application.
  By design, the user's JWT is provided to the protected application.
  The protected application could then use that JWT to access other protected applications.
- Manipulation of the Redis store.
  Gafaelfawr assumes the Redis store does not require authentication.
  An attacker with access to the Kubernetes network likely will be able to gain access to anything in Redis.
  The important information is encrypted and integrity-protected, but an attacker with Redis access could trivially cause a denial of service by deleting user sessions.

Mitigation details
==================

Gafaelfawr uses four secure storage artifacts:

- A JWT.
  The contents are readable by anyone but the integrity is protected by a public key signature.
  Gafaelfawr uses the ``RS256`` algorithm, which uses a 2048-bit RSA key.
  JWT signing and validation is done using the `PyJWT <https://pyjwt.readthedocs.io/en/latest/>`__ library.
- A session handle.
  Possession of a session handle proves the right to access and use the underlying JWT stored in the session.
  A session handle has two components: the key and a secret.
  The key is visible to anyone who can list the keys in the Gafaelfawr Redis store and, for user-issued tokens, is visible on the page listing of currently-issued tokens.
  Security of the system does not rely on keeping the key confidential.
  Proof of possession comes from the secret portion of the session handle, which must match the secret value stored inside the encrypted session for the session handle to be valid.
  The secret is a 128-bit random value generated using :py:func:`os.urandom`.
- A session cookie.
  Gafaelfawr uses an encrypted cookie to store the session handle for a browser authentication session, as well as other security-sensitive secrets (the CSRF token, the random state for OAuth 2.0 or OpenID Connect authentication).
  This cookie is encrypted using `~cryptography.fernet.Fernet`.
- Redis session store.
  Sessions stored in Redis, which include the secret value used to verify the session handle and the signed JWT for the user, are encrypted using `~cryptography.fernet.Fernet`.
  The key used is the same key used for encrypting the session cookie.
  Gafaelfawr also stores an index of user-issued tokens for a given user.
  This information is not particularly sensitive (it only contains the key of the session plus some other metadata about the token) and therefore is not encrypted or otherwise protected.

During initial authentication, Gafaelfawr sends a ``state`` parameter to the OAuth 2.0 or OpenID Connect authentication provider and also stores that parameter in the session cookie.
On return from authentication, the ``state`` parameter returned by the authentication provider is compared to the value in the session cookie and the authentication is rejected if they do not match.
This protects against session fixation (an attacker tricking a user into authenticating as the attacker instead of the user, thus giving the attacker access to data subsequently uploaded to the user).
The state value is a 128-bit random value generated using :py:func:`os.urandom`.

CSRF tokens are generated whenever returning a form and also stored in the session cookie.
On form submission, the CSRF token in the POST data is compared to the CSRF token in the session cookie and the POST is rejected if they do not match.
The CSRF token is generated by `aiohttp_csrf <https://github.com/shaqarava/aiohttp-csrf>`__.

The ``/login`` and ``/logout`` routes redirect the user after processing.
The URL to which to redirect the user may be specified as a GET parameter or, in the case of ``/login``, an HTTP header that is normally set by the nginx ingress.
To protect against open redirects, the specified redirect URL must be on the same host as the host portion of the incoming request for the ``/login`` or ``/logout`` route.
``X-Forwarded-For`` headers (expected to be set by the nginx ingress) are trusted for the purposes of determining the host portion of the request.

To-do
-----

- Content-Security-Policy, particularly for the ``/auth/tokens`` routes.
- Investigate whether the ``Forwarded`` header should be used instead for determining the hostname of an incoming request, and whether more validation can be done on the header.
- Logging is not yet systematic or documented.
- Optionally do not expose the user's JWT to a protected application.
- Explore using the nascent support for token reissuance to provide more protection against reuse of JWTs by protected applications.
