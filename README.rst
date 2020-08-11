##########
Gafaelfawr
##########

|Build| |Docker|

Gafaelfawr is an aiohttp application for the authorization and management of tokens, including the issuance and revocation of tokens.

Gafaelfawr is primarily an implementation of the `Token Proxy component <https://dmtn-094.lsst.io/#token-proxy>`__ identified in `DMTN-094 <https://dmtn-094.lsst.io>`__.

It authorizes tokens in according to the Nginx's ``auth_request`` directive via it's ``/auth`` endpoint and handles integration with an external identity provider (either with GitHub or OpenID Connect).
Authentication sessions are stored in Redis.
It also provides a minimal OpenID Connect server to support protected applications that only understand OpenID Connect.

For full documentation, see `gafaelfawr.lsst.io <https://gafaelfawr.lsst.io/>`__.

Gafaelfawr is named for Glewlwyd Gafaelfawr, the knight who challenges King Arthur in *Pa gur yv y porthaur?* and, in later stories, is a member of his court and acts as gatekeeper.
Gafaelfawr is pronounced (very roughly) gah-VILE-fahwr.
(If you speak Welsh and can provide a better pronunciation guide, please open an issue!)

.. |Build| image:: https://github.com/lsst-sqre/gafaelfawr/workflows/CI/badge.svg
   :alt: GitHub Actions
   :scale: 100%
   :target: https://github.com/lsst-sqre/gafaelfawr/actions

.. |Docker| image:: https://img.shields.io/docker/v/lsstsqre/gafaelfawr?sort=semver
   :alt: Docker Hub repository
   :scale: 100%
   :target: https://hub.docker.com/repository/docker/lsstsqre/gafaelfawr
