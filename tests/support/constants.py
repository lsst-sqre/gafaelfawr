"""Constants used in test fixtures and setup."""

TEST_DATABASE_URL = (
    "postgresql://gafaelfawr:INSECURE-PASSWORD@127.0.0.1/gafaelfawr"
)
"""The URL used for the test database.

This must match the ``tox.ini`` configuration for the PostgreSQL container.
"""

TEST_HOSTNAME = "example.com"
"""The hostname used in ASGI requests to the application."""
