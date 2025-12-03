"""Templated responses.

Since the primary UI is provided by Squareone_, these are used only for error
messages.
"""

from __future__ import annotations

from fastapi.templating import Jinja2Templates
from jinja2 import Environment, PackageLoader

__all__ = ["templates"]

templates = Jinja2Templates(
    env=Environment(
        loader=PackageLoader("gafaelfawr", package_path="templates"),
        autoescape=True,
    ),
)
"""The template manager."""
