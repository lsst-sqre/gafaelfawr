"""InfluxDB authentication service."""

from __future__ import annotations

from datetime import datetime, timezone

import jwt

from ..config import InfluxDBConfig
from ..models.token import TokenData

__all__ = ["InfluxDBService"]


class InfluxDBService:
    """Issue a new InfluxDB token.

    Parameters
    ----------
    config : `gafaelfawr.config.InfluxDBConfig`
        Configuration parameters.
    """

    def __init__(self, config: InfluxDBConfig) -> None:
        self._config = config

    def issue_token(self, token_data: TokenData) -> str:
        """Issue an InfluxDB-compatible token.

        InfluxDB requires an HS256 JWT with ``username`` and ``exp`` claims
        using a shared secret.  Issue such a token based on the user's
        Gafaelfawr token.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The data from the user's authentication token.

        Returns
        -------
        influxdb_token : `str`
            The encoded form of an InfluxDB-compatible token.
        """
        username = self.username_for_token(token_data)
        now = datetime.now(timezone.utc)
        if token_data.expires:
            expires = token_data.expires
        else:
            expires = now + self._config.lifetime
        payload = {
            "exp": int(expires.timestamp()),
            "iat": int(now.timestamp()),
            "username": username,
        }
        return jwt.encode(payload, self._config.secret, algorithm="HS256")

    def username_for_token(self, token_data: TokenData) -> str:
        """Determine the InfluxDB username for a given user.

        Depending on the configuration, we may use the same username for all
        InfluxDB tokens or we may use the username from the Gafaelfawr token.
        This method encapsulates that decision, which is used both by token
        issuance and by logging in the route handler.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The data from the user's authentication token.

        Returns
        -------
        username : `str`
            The InfluxDB username.
        """
        if self._config.username:
            return self._config.username
        else:
            return token_data.username
