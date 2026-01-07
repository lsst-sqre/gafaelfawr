"""Helper functions for reading test data."""

import json
from pathlib import Path
from typing import Any

from rubin.gafaelfawr import GafaelfawrUserInfo

__all__ = [
    "data_path",
    "read_test_json",
    "read_test_user_info",
]


def data_path(fragment: str) -> Path:
    """Construct a path to a test data file.

    Parameters
    ----------
    fragment
        Path relative to :file:`tests/data`.

    Returns
    -------
    Path
        Full path to file.
    """
    return Path(__file__).parent.parent / "data" / fragment


def read_test_json(fragment: str) -> Any:
    """Read test data as JSON and return its decoded form.

    Parameters
    ----------
    fragment
        Path relative to :file:`tests/data`.

    Returns
    -------
    typing.Any
        Parsed contents of the file.
    """
    path = data_path(fragment + ".json")
    with path.open("r") as f:
        return json.load(f)


def read_test_user_info(username: str) -> GafaelfawrUserInfo:
    """Read test user information for a user.

    Parameters
    ----------
    username
        Username whose test data should be read.

    Returns
    -------
    GafaelfawrUserInfo
        Parsed contents of the file.
    """
    raw_user_info = read_test_json(f"userinfo/{username}")
    return GafaelfawrUserInfo.model_validate(raw_user_info)
