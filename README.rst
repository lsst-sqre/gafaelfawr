##########
Gafaelfawr
##########

|Build|

Gafaelfawr is a `FastAPI`_ application for the authorization and management of tokens, including their issuance and revocation.

.. _FastAPI: https://fastapi.tiangolo.com/

Gafaelfawr started as an implementation of the `Token Proxy component <https://dmtn-094.lsst.io/#token-proxy>`__ identified in `DMTN-094 <https://dmtn-094.lsst.io>`__.
It has been subsequently simplified along the lines discussed in `SQR-039 <https://sqr-039.lsst.io/>`__ and contains an (as yet partial) implementation of the token management API defined in `SQR-049 <https://sqr-049.lsst.io/>`__.

It authorizes tokens in according to the Nginx's ``auth_request`` directive via it's ``/auth`` endpoint and handles integration with an external identity provider (either with GitHub or OpenID Connect).
Authentication sessions and user identity information are stored in Redis.
Token information is stored in a SQL database.
It also provides a minimal OpenID Connect server to support protected applications that only understand OpenID Connect.

For full documentation, see `gafaelfawr.lsst.io <https://gafaelfawr.lsst.io/>`__.

Gafaelfawr is named for Glewlwyd Gafaelfawr, the knight who challenges King Arthur in *Pa gur yv y porthaur?* and, in later stories, is a member of his court and acts as gatekeeper.
Gafaelfawr is pronounced (very roughly) gah-VILE-vahwr.
(If you speak Welsh and can provide a better pronunciation guide, please open an issue!)

.. |Build| image:: https://github.com/lsst-sqre/gafaelfawr/workflows/CI/badge.svg
   :alt: GitHub Actions
   :scale: 100%
   :target: https://github.com/lsst-sqre/gafaelfawr/actions
