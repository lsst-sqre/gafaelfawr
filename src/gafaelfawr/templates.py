"""Templated responses.

Since the primary UI is provided by JavaScript, these are generally used only
for error messages.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

__all__ = ["templates"]

# Starlette forces use of the FileSystemLoader and FastAPI re-exports the
# Starlette Jinja2Templates object, so we unfortunately cannot use
# importlib.resources or the equivalent here.
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
"""The template manager."""
