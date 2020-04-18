##########
Change log
##########

0.3.0 (unreleased)
==================

With this release, JWT Authorizer has been rewritten to use aiohttp instead of Flask.
There are corresponding substantial changes to how the application is started, which are reflected in the Docker configuration.
A new configuration key, ``session_secret`` is now required and is used to encrypt the session cookie (replacing ``flask_secret``).

- Rewrite using aiohttp and aioredis instead of Flask and redis.
- Add support for GitHub authentication.
  This is done via a new ``/login`` route and support for authentication credentials stored in a cookie.
- Add a (partial) manual.
  The formatted text is published at `jwt-authorizer.lsst.io <https://jwt-authorizer.lsst.io>`__.
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
