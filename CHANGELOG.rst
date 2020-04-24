##########
Change log
##########

1.0.0 (2020-04-24)
==================

JWT Authorizer has been renamed to Gafaelfawr.
It is named for Glewlwyd Gafaelfawr, the knight who challenges King Arthur in *Pa gur yv y porthaur?* and, in later stories, is a member of his court and acts as gatekeeper.
Gafaelfawr is pronounced (very roughly) gah-VILE-fahwr.

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
