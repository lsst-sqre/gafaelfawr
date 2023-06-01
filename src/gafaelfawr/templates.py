"""Templated responses.

Since the primary UI is provided by JavaScript, these are generally used only
for error messages.
"""

from __future__ import annotations

from fastapi.templating import Jinja2Templates
from jinja2 import PackageLoader

__all__ = ["templates"]

# Starlette requires a directory argument, but since we override the loader so
# that the templates are retrieved from the Python package, it's unused.
templates = Jinja2Templates(
    loader=PackageLoader("gafaelfawr", package_path="templates"),
    directory="templates",
)
"""The template manager."""
