# Gafaelfawr

[![Build](https://github.com/lsst-sqre/gafaelfawr/workflows/CI/badge.svg)](https://github.com/lsst-sqre/gafaelfawr/actions)

Gafaelfawr is a [FastAPI](https://fastapi.tiangolo.com/) service for the authorization and management of tokens, including their issuance and revocation.

It is part of the Rubin Science Platform identity management system.
The overall design is documented in [DMTN-234](https://dmtn-234.lsst.io), and its implementation in [DMTN-224](https://dmtn-224.lsst.io).
History and decisions made during its development are documented in [SQR-069](https://sqr-069.lsst.io).
Read those documents for a more complete picture of how Gafaelfawr fits into a larger identity management system.

Gafaelfawr provides authentication and access control via NGINX's `auth_request` directive, and handles integration with an external identity provider (either with GitHub or OpenID Connect).
Authentication sessions and user identity information are stored in Redis.
Token information is stored in a SQL database.
It also provides an API (and currently a UI) to create and manipulate tokens, and a minimal OpenID Connect server to support protected services that only understand OpenID Connect.

For full documentation, see [gafaelfawr.lsst.io](https://gafaelfawr.lsst.io/).

Gafaelfawr is named for Glewlwyd Gafaelfawr, the knight who challenges King Arthur in *Pa gur yv y porthaur?* and, in later stories, is a member of his court and acts as gatekeeper.
Gafaelfawr is pronounced (very roughly) gah-VILE-vahwr.
(If you speak Welsh and can provide a better pronunciation guide, please open an issue!)
