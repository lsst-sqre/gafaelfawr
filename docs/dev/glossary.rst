########
Glossary
########

There are a lot of possibly-unfamiliar terms with sometimes-varying meanings in the world of web authentication.
Here are the terms as used in Gafaelfawr.
The below definitions of terms should be used consistently throughout the documentation and code, including in variable naming and function and method names.

claim
    A single key/value pair contained in the payload of a JWT.
    Represents some fact about either the user represented by the JWT or the JWT itself (such as its issue or expiration date).
    A collection of multiple claims may be referred to as claims, although payload is preferred if they are intended as the complete contents of a JWT.

identity provider
    Often shortened to "provider," this is a system that can authenticate a user and provide their identity information to other systems.
    This may be via the OpenID Connect protocol or (as with GitHub) some other protocol such as OAuth 2.0.

issue
    To create a new authentication token, either Gafaelfawr's own token or a JWT.

issuer
    An entity that issues JWTs.
    Each issuer is identified by a unique URI, which goes into the ``iss`` claim of JWTs it issues.

JWKS
    A JSON key set.
    Roughly the JSON equivalent of a PEM-encoded public key, except that it can hold a broader range of keys.
    This is how public keys are communicated in the JWT world.

JWT
    A JSON web token, consisting of a header, a set of claims, and a signature.
    The set of claims is also called a payload.
    A JWT is the signed and serialized version; the claims alone without the header and signature are referred to as the payload.

key ID
    Also known as ``kid``, which is the JSON key for it in a JWKS or in the header of a JWT, this identifies which key of an issuer was used to sign a JWT.

payload
    The claims portion of a JWT.
    Consists of key/value pairs.
    The value is normally a `str` but may be an `int` or a more complex structure.

protected service
    A service that uses Gafaelfawr for authentication and authorization.
    Gafaelfawr will run as an NGINX auth subrequest handler and return headers that NGINX will in turn pass to the protected service, which it can use for further authorization and identity decisions.

scope
    The term "scope" is unfortunately overloaded.
    It is used both for a set of permissions granted to a Gafaelfawr token and for a set of claims requested from an OpenID Connect server.

    For a token issued by Gafaelfawr, a scope represents a general class of permissions on systems protected by Gafaelfawr.
    Services can be protected by authorization rules that require specific scopes.

    When requesting authentication from an OpenID Connect provider, including the Gafaelfawr OpenID Connect provider, the requested scopes control what information is returned about the user in the ID token.
    These scopes are (partly) standardized by the OpenID Connect standard and are entirely unrelated to (and have a different naming convention than) Gafaelfawr scopes.

session
    A stored authentication token for a user that expires after some set length of time.
    Sessions are stored in an encrypted cookie named ``gafaelfawr``.
    The cookie will include a token if the user is authenticated.
    It may contain other state information for the login process, a CSRF token, or other state used internally by Gafaelfawr.
    Session cookies are encrypted in a key known only to the Gafaelfawr service, but act as bearer credentials (so must be kept secure from theft by attackers).

subject
    The identity of an entity that authenticates with a JWT.
    Alternately, the identity represented by that JWT.
    This term is widely used in authentication systems but is not used internally by Gafaelfawr.

token
    There are two types of authentication tokens used by Gafaelfawr.
    When authenticating the user to an external OpenID Connect service, or when acting as an OpenID Connect service to a protected service, the ID token is a JWT.
    For all other operations, including the access token returned when acting as an OpenID Connect service, tokens are opaque strings starting with ``gt-``.
    These opaque tokens consist of two parts: a key and a secret.
    The key is the Redis key for the stored session.
    The secret proves that the client has the right to use that stored session.

UID
    A numeric ID for a user, suitable for use as a POSIX UID.
    Confusingly, LDAP, and thus claims based on LDAP attributes, use ``uid`` to store what is known everywhere else as the username, and use ``uidNumber`` to store the UID.
    Gafaelfawr always uses UID to refer to the numeric identifier.

username
    A short string identifying a user, suitable for use as a POSIX username.
    Conventionally this does not include an ``@`` or domain (see the user's email address for that).

verify
    To check the signature and validity of a JWT.
    This includes retrieving the key used to sign it from its issuer, ensuring that is one of the expected keys if the list of valid keys is restricted, and checking that all the expected claims are present.

Terms to avoid
==============

Gafaelfawr avoids the following terms.

attribute
    Except when referring to LDAP or GitHub API results, an attribute doesn't clearly map to a component of a JWT-based authentication system.
    The intended term is probably "claim."

capability
    Use "scope" instead.
