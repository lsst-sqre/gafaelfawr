#######
Storage
#######

For details on how tokens are stored in Gafaelfawr, see the more substantial discussion in `SQR-049 <https://sqr-049.lsst.io/>`__.

Session cookie
==============

Sessions in Gafaelfawr are stored in a session cookie.
The session cookie is also used to store some other transient information.

The Gafaelfawr session cookie is JSON, encrypted with :py:class:`~cryptography.fernet.Fernet`.
The cookie may contain the following keys:

``csrf``
    A CSRF value, which must match the corresponding form parameter on submission.
    Used to protect against cross-site request forgery.
    Set when returning a web page that contains forms.

``return_url``
    The URL to which the user should be returned after authentication is complete.
    This will be set only while there is an outstanding external authentication request.

``state``
    The random state value used to protect external authentication against session fixation.
    This will be set only while there is an outstanding external authentication request.

``token``
    The user's authentication token.

Authorization codes
===================

Authorization codes returned by the OpenID Connect server are stored in Redis in a way very similar to tokens.
The authorization code uses the same data structure and representation as a token, except with a ``gc-`` prefix instead of ``gt-``.
Authorizations are stored under a Redis key of ``oidc:<key>`` where ``<key>`` is the key from the code.
The value os JSON-encrypted with :py:class:`~cryptography.fernet.Fernet`.
The decrypted authorization has the following keys:

``code``
    The full authoriztaion code, including the secret, which must match the presented code.
    The code is stored as a JSON object with two keys, ``key`` and ``secret``, corresponding to the two parts of the code.

``client_id``
    The client ID for whom the authorization was issued.

``redirect_uri``
    The redirect URI presented at the time of code issuance.

``token``
    The token for the underlying authorization session.
    This is used to retrieve the user's token for JWT issuance.

``created_at``
    The time at which the authorization code was created in integer seconds since epoch.

Authorization codes are valid for one hour.
They are single-use.
Once the authorization code has been redeemed, the authorization is deleted from Redis.
