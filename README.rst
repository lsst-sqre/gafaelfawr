##########
Gafaelfawr
##########

Gafaelfawr is an aiohttp application for the authorization and management of tokens, including the issuance and revocation of tokens.

Gafaelfawr is primarily an implementation of the `Token Proxy component <https://dmtn-094.lsst.io/#token-proxy>`__ identified in `DMTN-094 <https://dmtn-094.lsst.io>`__.

It can authorize tokens in according to the Nginx's ``auth_request`` directive via it's ``/auth`` endpoint, but it's primarily set up in a deployment with oauth2_proxy (in proxy mode) and Redis.
This allows oauth2_proxy to handle authentication and Gafaelfawr to handle authorization and token management.

For full documentation, see `jwt-authorizer.lsst.io <https://jwt-authorizer.lsst.io/>`__.

Gafaelfawr is named for Glewlwyd Gafaelfawr, the knight who challenges King Arthur in *Pa gur yv y porthaur?* and, in later stories, is a member of his court and acts as gatekeeper.
Gafaelfawr is pronounced (very roughly) gah-VILE-fahwr.
(If you speak Welsh and can provide a better pronunciation guide, please open an issue!)
