##########
Change log
##########

3.0.1 (unreleased)
==================

- Display the token key and token type when showing token change history.
  Since the change history includes subtokens, not showing the type or key was confusing.
- Initialize the database if needed as part of Gafaelfawr container startup.
- Add additional startup logging at the DEBUG level.
- Improve error reporting if Gafaelfawr is unable to connect to its database.
- Update dependencies.

3.0.0 (2021-05-18)
==================

This release replaces the Kubernetes secret management approach released with 2.0.0 with a new approach based on a ``GafaelfawrServiceToken`` custom resource definition.
The old configuration-based approach is no longer supported.

- Add new ``kubernetes-controller`` invocation, which reconciles all ``GafaelfawrServiceToken`` objects and then starts a watcher and processes new updates as they happen.
- Change ``update-service-tokens`` to use the custom resource approach instead of configuration plus labeled Kubernetes ``Secret`` objects.
- Use local Kubernetes configuration for Kubernetes operations if invoked outside of a Kubernetes cluster.
- Increase the timeout for outbound HTTP calls to authentication providers to 20 seconds.
  Some authentication providers and some Kubernetes cluster networking environments can be surprisingly slow.
- Update dependencies.

2.0.1 (2021-04-26)
==================

- Cap workers spawned by the Docker image at 10.
  The defaults spawned 32 workers in a GKE container, which overwhelmed the available open connections with a micro Cloud SQL server.
- Update JavaScript dependencies.

2.0.0 (2021-04-23)
==================

As of this release, Gafaelfawr now uses opaque tokens for all internal authentication and only issues JWTs as part of its OpenID Connect server support.
All existing sessions and tokens will be invalidated by this upgrade and all users will have to reauthenticate.

Gafaelfawr now requires a SQL database.
Its URL must be set as the ``config.databaseUrl`` Helm chart parameter.

As of this release, Gafaelfawr now uses FastAPI instead of aiohttp.
OpenAPI documentation is available via the ``/auth/docs`` and ``/auth/redoc`` routes.

- Eliminate internal JWTs, including the old session and session handle system, in favor of opaque tokens.
- Add a new token API under ``/auth/api/v1`` for creating, modifying, viewing, and deleting tokens.
  This is the basis of the new token management UI.
  API documentation is published under ``/auth/docs`` and ``/auth/redoc``.
- Add support for several classes of tokens for different purposes.
  Add additional token metadata to record the purpose of a token.
- Add caching of internal and notebook tokens.
  Issue new internal and notebook tokens when the previous token is half-expired.
- Add support for a bootstrap token that can be used to dynamically create other tokens or configure administrators.
- Add support for maintaining Kubernetes secrets containing Gafaelfawr service tokens for applications that need to make authenticated calls on their own behalf.
- Replace the ``/auth/tokens`` UI with a new UI using React and Gatsby.
  Currently, it supports viewing all the tokens for a user, creating and editing user tokens, revoking tokens, viewing token information with the token change history, and searching the token change history.
- Protected applications no longer receive a copy of the user's authentication token.
  They must request a delegated token if they want one.
- The ``/auth`` route now supports requesting a notebook or internal delegated token for the application.
- Use FastAPI instead of aiohttp, and use httpx to make internal requests.
- Add ``/.well-known/openid-configuration`` route to provide metadata about the internal OpenID Connect server.
  This follows the OpenID Connect Discovery 1.0 specification.
- Enforce constraints on valid usernames matching GitHub's constraints, except without allowing capital letters.
- Be more careful in interpreting ``isMemberOf`` claims from the upstream OpenID Connect provider and discard more invalid data.
- Only document and support installing Gafaelfawr via the Helm chart.
- Update all dependencies.

1.5.0 (2020-09-16)
==================

This release fixes some issues with the InfluxDB token issuance support.

- Put the username in the ``username`` field of InfluxDB tokens, not ``sub``.
- Add a new configuration option, ``issuer.influxdb_username``, and a new Helm chart parameter, ``issuer.influxdb.username``, to force the username field of all issued InfluxDB tokens to a single value.
  This is useful if one does not want to do user management in InfluxDB and is content with granting all users access to a generic account.

1.4.1 (2020-09-11)
==================

This release fixes some bugs in the internal OpenID Connect support uncovered by testing with Chronograf.

- Fix data type of the ``expires_in`` data element returned by the ``/auth/openid/token`` endpoint.
  Expiration time in seconds must be truncated to an integer per the relevant standard.
- Fix encoding of the internal JWKS.
  The relevant standard requires the padding be omitted from the end of the encoding.

1.4.0 (2020-08-13)
==================

This release adds a minimalist OpenID Connect server to support protected applications that only understand OpenID Connect.
The initial implementation is intended to support `Chronograf <https://www.influxdata.com/time-series-platform/chronograf/>`__.
Other applications may or may not work.
It also adds optional support for issuing InfluxDB authentication tokens.

- Add support for a password-protected Redis backend.
  This uses a new configuration parameter, ``redis_password_file``, which points to a file containing the password for Redis.
- Add a minimalist OpenID Connect server.
  The secrets for client connections are read from a file designed by a new configuration parameter, ``oidc_server_secrets_file``.
  The authentication endpoint is ``/auth/openid/login`` and the token endpoint is ``/auth/openid/token``.
- Add a user information endpoint (``/auth/userinfo``) that accepts a JWT and returns its claims.
  Intended primarily for use with OpenID Connect.
- Add support for issuing InfluxDB authentication tokens via a new ``/auth/tokens/influxdb/new`` route.
  InfluxDB requires JWTs with the HS256 algorithm and a shared secret.
  This feature is enabled by configuring the shared secret via the ``issuer.influxdb_secret_file`` configuration option.

1.3.2 (2020-06-08)
==================

- Work around an NGINX ingress bug in 1.39.1 by allowing multiple ``X-Forwarded-Proto`` headers in the incoming request.
- Document how to configure NGINX ingress with the official Helm chart to support logging accurate client IPs.

1.3.1 (2020-05-29)
==================

This release drops support for Python 3.7.
Python 3.8 or later is now required.

- Require Python 3.8 and drop Python 3.7 support.
- Include ``token_source`` in logs of the ``/auth`` route to record how the client passed in the authentication token.
- Set the ``X-Auth-Request-Client-Ip`` header to the calculated client IP on a successful reply from the ``/auth`` route.
- The output from the ``/auth/analyze`` route is now sorted and formatted to be easier for humans to read and compare.
- Include more information in the user-facing error message when a connection to the authentication provider's callback endpoint fails.
- Report a better error message if the OpenID Connect provider doesn't have a JWKS entry for the key ID of the identity token.

1.3.0 (2020-05-19)
==================

This release changes the construction of identity and groups from GitHub authentication by coercing identifiers to lowercase.
GitHub is case-preserving but case-insensitive, which is complex for protected applications to deal with.
This change ensures Gafaelfawr exposes a consistent canonical identity to downstream applications that is also compatible with other systems that expect lowercase identifiers, such as Kubernetes namespaces.

- Lowercase GitHub usernames when constructing identity tokens.
- Lowercase GitHub organization names when constructing group membership.

1.2.1 (2020-05-14)
==================

Gafaelfawr can now analyze the ``X-Forwarded-For`` header to determine the true client IP for logging purposes.
This requires some configuration of both Gafaelfawr and the NGINX ingress.
See `the logging documentation <https://gafaelfawr.lsst.io/logging.html#client-ip-addresses>`__ for more information.

- Add new ``proxies`` setting to configure what network blocks should be treated as internal to the Kubernetes cluster.
- Set the client IP to the right-most IP in ``X-Forwarded-For`` that is not in a network block listed in ``proxies``.
- Document the necessary NGINX ingress configuration for ``X-Forwarded-For`` analysis to work correctly.
- Fall back on logging ``X-Original-URL`` if ``X-Original-URI`` is not set.
- Stop recommending setting the ``auth-request-redirect`` annotation and do recommend setting the ``auth-method`` annotation.

1.2.0 (2020-05-07)
==================

New in this release is an ``/auth/forbidden`` route that can be used to provide a non-cached 403 error page.
See `the documentation <https://gafaelfawr.lsst.io/install.html#disabling-error-caching>`__ for more information.

This release changes Gafaelfawr's logging format and standardizes the contents of the logs.
All logs are now in JSON.
See `the new logging documentation <https://gafaelfawr.lsst.io/logging.html>`__ for more information.

- Default to JSON logging (controlled via ``SAFIR_PROFILE``)
- Add remote IP and ``User-Agent`` header field values to all logs.
- Add more structured information to authentication logging.
- Ensure each route logs at least one event.

1.1.1 (2020-04-29)
==================

- Include any errors from the external OpenID Connect provider in the error message if retrieving an ID token fails.
  Previous versions only reported a generic error message, which was missing error details from the JSON body of the upstream error, if available.

1.1.0 (2020-04-28)
==================

This release overhauls configuration parsing and removes use of Dynaconf.
As a result, the top-level environment key in configuration files is no longer required (or supported).
All configuration settings should now be at the top level.

This release also adds support for specifying the type of authentication challenges to unauthenticated users.

- Replace Dyanconf with pydantic for configuration parsing.
  This should produce much better diagnostics for invalid configuration files.
  This also eliminates the Dynaconf environment key that was previously expected to be the top-level key of the configuration file.
  Existing configuration files will need to be flattened by removing that key and elevating configuration settings to the top level.
- Add support for an ``auth_type`` parameter to the ``/auth`` route.
  This can be set to ``basic`` to request that unauthenticated users be challenged for Basic authentication instead of Bearer.
  That in turn will cause pop-up authentication prompting in a web browser.
- Fix syntax of ``WWW-Authenticate`` challenges and return them in more cases.
  Attempt to properly implement RFC 6750, including using proper ``error`` attributes, including challenges in some 400 and 403 replies, and including the ``scope`` attribute where appropriate.
- Return 403 instead of 401 for unauthenticated AJAX requests.
  401 triggers the redirect handling in ingress-nginx, but this is pointless for AJAX requests, which cannot navigate the redirect to an external authentication provider.
  Worse, AJAX requests may be frequently retried on error (such as an expired credential), which if redirected can create a low-grade denial of service attack on the authentication provider, trigger rate limiting, and cause other issues.
  AJAX requests, as detected by ``X-Requested-With: XMLHttpRequest`` in the request headers, now get a 403 reply if they have missing or expired credentials.

1.0.0 (2020-04-24)
==================

JWT Authorizer has been renamed to Gafaelfawr.
It is named for Glewlwyd Gafaelfawr, the knight who challenges King Arthur in *Pa gur yv y porthaur?* and, in later stories, is a member of his court and acts as gatekeeper.
Gafaelfawr is pronounced (very roughly) gah-VILE-vahwr.

As of this release, Gafaelfawr supports OpenID Connect directly and no longer uses oauth2_proxy.
There are new options to configure the OpenID Connect support.

The configuration has been substantially overhauled in this release and many configuration options have changed names.
Please review the documentation thoroughly before upgrading.

- Rename the application to Gafaelfawr and the Python package to gafaelfawr.
- Add native support for OpenID Connect.
- Fix a security weakness where a user could request a token with any known scope, regardless of the scopes of their own authentication token.
  The scopes of user-issued tokens are now limited to the scopes of the token used to authenticate to the token creation page.
- The ``/auth`` route now takes a ``scope`` parameter instead of a ``capability`` parameter to specify the scopes required for authorization.
- Rename ``Capability`` to ``Scope`` in the headers exposed after successful authorization.
- Overhaul how authentication sessions and user-issued tokens are stored in Redis.
  This will invalidate all existing sessions and user-issued tokens on upgrade.
  Sessions are now encrypted with Fernet rather than with the complex encryption required for oauth2_proxy compatibility.
- Significantly overhaul the configuration settings.
  Delete the unused configuration options ```www_authenticate``, ``no_authorize``, ``no_verify``, and ``set_user_headers``.
  Eliminate the ``issuers`` setting in favor of configuring the upstream issuer in the OpenID Connect configuration.
  Rename the configuration settings for the internal issuer.
- Always set the ``scope`` claim when issuing internal tokens, based on group membership, and only check the ``scope`` claim during authorization.
- Add a new ``/logout`` route.
- Simplify token verification for internally-issued tokens and avoid needless HTTP requests to the JWKS route.
- Require that all tokens have claims for the username and UID (the claim names are configurable).
- Add ``/oauth2/callback`` as an alias for the ``/login`` route for backwards compatibility with oauth2_proxy deployments.
- Drop support for reading tokens from ``X-Forwarded-Access-Token`` or ``X-Forwarded-Ticket-Id-Token`` headers.
- Protect against open redirects in the ``/login`` route.
  The destination URL now must be at the same host as the ``/login`` route.
- Add the ``generate-key`` CLI command to ease generation of a new signing key.
- Remove support for configuring secrets directly and only read them from files.
  It simplifies the code and improves testing to have only one mechanism of secret management.
- Improve logging somewhat (although it's still not structured or documented).
- Cleanly shut down Redis connections when shutting down the server.
- Add architecture documentation and a glossary of terms to the manual.
- Flesh out the Kubernetes installation documentation and document the standard Helm chart.

0.3.0 (2020-04-20)
==================

With this release, JWT Authorizer has been rewritten to use aiohttp instead of Flask.
There are corresponding substantial changes to how the application is started, which are reflected in the Docker configuration.
A new configuration key, ``session_secret`` is now required and is used to encrypt the session cookie (replacing ``flask_secret``).

- Rewrite using aiohttp and aioredis instead of Flask and redis.
- Add support for GitHub authentication.
  This is done via a new ``/login`` route and support for authentication credentials stored in a cookie.
- Add a (partial) manual.
  The formatted text is published at `gafaelfawr.lsst.io <https://gafaelfawr.lsst.io>`__.
  Included are partial installation instructions, a guide to configuration settings, and API documentation.
- Add support for serving ``/.well-known/jwks.json`` for the internal token signing key, based on the configured private key.
  A separate static web service is no longer required.
- Remove support for authorization plugins and always do authorization based on groups.
  None of the Rubin Observatory configurations were using this support, and it allows significant code simplification.
- Allow GET requests to ``/analyze`` and return an analysis of the user's regular authentication token.
- Trust ``X-Forwarded-For`` headers (primarily for logging purposes).
- Remove some unused configuration options.
- Add improved example configuration files in ``example``.
- Significantly restructure the code to hopefully make the code more maintainable.
- Significantly expand the test suite.
- Support (and test) Python 3.8.
- Change the license to MIT from GPLv3.

0.2.2 (2020-03-19)
==================

- Fix decoding of dates in the ``oauth2_proxy`` session.

0.2.1 (2020-03-18)
==================

- Fix misplaced parameter when decoding tokens in the ``/auth`` route.

0.2.0 (2020-03-16)
==================

- Add ``/auth/analyze`` route that takes a token or ticket via the ``token`` POST parameter and returns a JSON analysis of its contents.
- Overhaul the build system to match other SQuaRE packages.
