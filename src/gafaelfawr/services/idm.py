"""IDM lookups for group information."""
from __future__ import annotations

from urllib.parse import urljoin

from httpx import AsyncClient, BasicAuth
from structlog.stdlib import BoundLogger

from ..config import IDMConfig

__all__ = ["IDMService"]


class IDMService:
    """Perform IDM lookups for group information.

    Parameters
    ----------
    config
        The IDM config.
    http_client
        The AsyncClient to use.
    logger
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: IDMConfig,
        http_client: AsyncClient,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._logger = logger
        self._http_client = http_client

    async def get_group_id(self, groupname="lsst") -> str:
        """Get the GID of a group from IDM.

        Parameters
        ----------
        groupname
            Name of the group, by default lsst.

        Returns
        -------
        str
         gid
            The gid if set, None otehrwise

        """
        base_url = self._config.url
        idm_id = self._config.idm_id
        idm_secret = self._config.idm_secret
        auth = BasicAuth(idm_id, idm_secret)
        # query='?_queryFilter=name+eq+"{}"&_fields=gid'.format(groupname)
        url = urljoin(base_url, self._build_gid_query(groupname))
        try:
            r = await self._http_client.get(url, auth=auth)
            result = r.json()
            gid = result.get("result")[0].get("gid")
        except IndexError:
            gid = None
        #     r.raise_for_status()
        return gid

    def _build_gid_query(
        self,
        groupname=str,
    ) -> str:
        """Return the query to run to get the GID of a group from IDM.

        Parameters
        ----------
        groupname
            Name of the group, by default lsst.

        Returns
        -------
        str
         query
            The query to run to get the GID from IDM

        """
        query = 'group?_queryFilter=name+eq+"{}"&_fields=gid'.format(groupname)
        return query
