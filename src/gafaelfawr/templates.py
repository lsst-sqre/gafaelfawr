"""Templated responses.

Since the primary UI is provided by JavaScript, these are generally used only
for error messages.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

__all__ = ["templates"]

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
"""The template manager."""
