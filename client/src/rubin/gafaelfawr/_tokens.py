"""Functions for creating tokens."""

import base64
import os

__all__ = ["create_token"]


def create_token() -> str:
    """Create a new random Gafaelfawr token.

    Normally, users of Gafaelfawr should use the Gafaelfawr API to create new
    tokens. This function is intended only for creating new bootstrap tokens
    that will be injected into the Gafaelfawr server via configuration, or for
    creating syntactically valid tokens for use with the Gafaelfawr mock.

    Returns
    -------
    str
        New random Gafaelfawr token. This token will not be registered with
        any running Gafaelfawr instance and therefore will not be usable
        without other measures, such as configuring it as a bootstrap token.
    """
    key = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
    secret = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
    return f"gt-{key}.{secret}"
