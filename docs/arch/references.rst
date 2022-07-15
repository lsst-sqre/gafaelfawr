##########
References
##########

Design documents
================

`DMTN-235: Token scopes for the Rubin Science Platform`__
    The authentication service for the Rubin Science Platform (Gafaelfawr) uses tokens to authenticate users.
    Each token is associated with a list of scopes, which are used to make authorization decisions.
    This tech note lists the scopes currently in use by the Science Platform, defines them, and discusses the services to which each scope grants access.

__ https://dmtn-235.lsst.io/

`SQR-039: Discussion of authentication and authorization for Science Platform`__
    This technote reassesses the authentication and authorization needs for the Science Platform in light of early operational experience and Data Facility developments, discusses trade-offs between possible implementation strategies, and proposes a modified design based on opaque bearer tokens and a separate authorization and user metadata service.

__ https://sqr-039.lsst.io/

`SQR-044: Science Platform identity management requirements`__
    The identity management component of the Science Platform holds the list of authorized users, their group information, bindings from those users to external authentication providers, and associated metadata for both users and groups, such as quotas and other limits.
    This document sets out the requirements for that component.
    It also flags the minimal requirements and the requirements already met by the current identity.lsst.org system.

__ https://sqr-044.lsst.io/

`SQR-049: Science Platform token management design`__
    Authentication tokens will be used by the science platform as web authentication credentials, for API and service calls from outside the Science Platform, and for internal service-to-service and notebook-to-service calls.
    This document lays out the technical design of the token management component, satisfying the requirements given in SQR-044.

__ https://sqr-049.lsst.io/

`DMTN-094: LSP Authentication Design`__
    This document covers core technologies and interactions between services, APIs, and applications interacting with the LSST Science Platform.
    This is the original design document, which has been partly replaced by the above documents.

__ https://dmtn-094.lsst.io/

Protocol references
===================

`CILogon OpenID Connect`__
    Documentation for how to use CILogon as an OpenID Connect provider.
    Includes client registration and the details of the OpenID Connect protocol as implemented by CILogon.

__ https://www.cilogon.org/oidc

`GitHub OAuth Apps`__
    How to create an OAuth App for GitHub, request authentication, and parse the results.

__ https://developer.github.com/apps/building-oauth-apps/

`GitHub Users API`__
    APIs for retrieving information about the authenticated user.
    See also `user emails <https://developer.github.com/v3/users/emails/>`__ and `teams <https://developer.github.com/v3/teams/>`__.

__ https://developer.github.com/v3/users/

`OpenID Connect Core 1.0`__
    The core specification of the OpenID Connect protocol.

__ https://openid.net/specs/openid-connect-core-1_0.html

`OpenID Connect Discovery 1.0`__
    OpenID Connect discovery mechanisms, including the specification for the metadata returned by the provider metadata endpoint.

__ https://openid.net/specs/openid-connect-discovery-1_0.html

`RFC 6749: The OAuth 2.0 Authorization Framework`__
    The specification for the OAuth 2.0 authorization framework, on top of which OpenID Connect was built.

__ https://tools.ietf.org/html/rfc6749

`RFC 6750: Bearer Token Usage`__
    Documents the syntax for ``WWW-Authenticate`` and ``Authorization`` header fields when using bearer tokens.
    The attributes returned in a challenge in a ``WWW-Authenticate`` header field are defined here.

__ https://tools.ietf.org/html/rfc6750

`RFC 7517: JSON Web Key (JWK)`__
    The specification of the JSON Web Key format, including JSON Web Key Sets (JWKS).

__ https://tools.ietf.org/html/rfc7517

`RFC 7519: JSON Web Token (JWT)`__
    The core specification for the JSON Web Token format.

__ https://tools.ietf.org/html/rfc7519

`RFC 7617: The Basic HTTP Authentication Scheme`__
    Documents the syntax for ``WWW-Authenticate`` and ``Authorization`` header fields when using HTTP Basic Authentication.

__ https://tools.ietf.org/html/rfc7617
