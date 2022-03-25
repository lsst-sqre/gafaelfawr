"""Constants used in test fixtures and setup."""

from gafaelfawr.keypair import RSAKeyPair

TEST_DATABASE_URL = (
    "postgresql://gafaelfawr:INSECURE-PASSWORD@127.0.0.1/gafaelfawr"
)
"""The URL used for the test database.

This must match the ``tox.ini`` configuration for the PostgreSQL container.
"""

TEST_HOSTNAME = "example.com"
"""The hostname used in ASGI requests to the application."""

TEST_KEYPAIR = RSAKeyPair.generate()
"""RSA key pair for upstream OpenID Connect tokens.

Generating this takes a surprisingly long time when summed across every test,
so generate one statically at import time for each test run and use it for
every OpenID Connect authentication provider test.
"""
