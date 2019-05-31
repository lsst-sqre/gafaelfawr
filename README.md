# JWT Authorizer

JWT Authorizer is a Flask application for the authorization and management
of tokens, including the issuance and revocation of tokens.

JWT Authorizer is primarily an implementation of the 
[Token Proxy component](https://dmtn-094.lsst.io/#token-proxy)
identified in  [DMTN-094](https://dmtn-094.lsst.io).

It can authorize tokens in according to the Nginx's`auth_request` directive 
via it's ``/auth`` endpoint, but it's primarily set up in a deployment
with oauth2_proxy (in proxy mode) and Redis. This allows oauth2_proxy
to handle authentication and JWT Authorizer to handle authorization and
token management.

## Token and Ticket Issuance

JWT Authorizer is itself a token issuer which oauth2_proxy is typically
configured to honor. In this mode, it can take third party tokens,
such as those from CILogon, Github, or Google, and reissue them
with appropriate lifetimes. It can also reissue tokens for internal
requests.

JWT Authorizer has a token issuer interface which can issue tokens 
directly, in the form of a ticket. JWT Authorizer does this by generating 
a new ticket and token, encrypting the token with part of the ticket and
storing it in Redis, returning the ticket to the user.

In future requests, oauth2_proxy knows to use the ticket to look up 
and decrypt the token from Redis, verify the token for authentication, 
and pass the token on to JWT authorizer's `/auth` endpoint for authorization.
