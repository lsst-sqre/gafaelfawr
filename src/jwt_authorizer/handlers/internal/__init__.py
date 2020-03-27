"""Internal HTTP handlers that serve relative to the root path, ``/``.

These handlers aren't externally visible since the app is available at a path,
``/auth``. See `jwt_authorizer.handlers.external` for the external endpoint
handlers.
"""

__all__ = ["get_index"]

from jwt_authorizer.handlers.internal.index import get_index
