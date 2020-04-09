##############
JWT Authorizer
##############

JWT Authorizer is an aiohttp application for the authorization and management of tokens, including the issuance and revocation of tokens.

JWT Authorizer is primarily an implementation of the `Token Proxy component <https://dmtn-094.lsst.io/#token-proxy>`__ identified in `DMTN-094 <https://dmtn-094.lsst.io>`__.

It can authorize tokens in according to the Nginx's ``auth_request`` directive via it's ``/auth`` endpoint, but it's primarily set up in a deployment with oauth2_proxy (in proxy mode) and Redis.
This allows oauth2_proxy to handle authentication and JWT Authorizer to handle authorization and token management.

For full documentation, see `jwt-authorizer.lsst.io <https://jwt-authorizer.lsst.io/>`__.
