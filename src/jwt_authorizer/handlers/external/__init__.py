"""External route handlers that serve relative to ``/auth``."""

__all__ = [
    "get_auth",
    "get_token_by_handle",
    "get_tokens",
    "get_tokens_new",
    "post_analyze",
    "post_delete_token",
    "post_tokens_new",
]

from jwt_authorizer.handlers.external.analyze import post_analyze
from jwt_authorizer.handlers.external.auth import get_auth
from jwt_authorizer.handlers.external.tokens import (
    get_token_by_handle,
    get_tokens,
    get_tokens_new,
    post_delete_token,
    post_tokens_new,
)
