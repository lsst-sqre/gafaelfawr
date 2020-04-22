################
Session handling
################

Sessions in Gafaelfawr are stored in two places: a session cookie, and a persistent session store.
These are connected by a session handle that can be stored in the session cookie and is used to retrieve the authentication session.
The session cookie is also used to store some other transient information.

Session cookie
==============

The Gafaelfawr session cookie is a :py:mod:`aiohttp_session` cookie using encrypted cookie storage.
The cookie contents are encrypted with :py:class:`~cryptography.fernet.Fernet`.
The cookie may contain the following keys:

``csrf``
    A CSRF value, which must match the corresponding form parameter on submission.
    Used to protect against cross-site request forgery.
    Set when returning a web page that contains forms.

``handle``
    A session handle, referencing a stored session.

``message``
    Used to pass messages from one page to another.
    Currently only used to present the user with a newly-created session handle after they issue themselves a new token.

``rd``
    The URL to which the user should be returned after authentication is complete.
    This will be set only while there is an outstanding external authentication request.

``state``
    The random state value used to protect external authentication against session fixation.
    This will be set only while there is an outstanding external authentication request.

Session handle
==============

A session handle stands in for a JWT.
The corresponding JWT is stored encrypted in the session storage.
Session handles are used instead of JWTs directly because they are much shorter, and therefore avoid various problems with long HTTP headers.

All session handles are of the form ``gsh-<key>.<secret>``.
The ``gsh-`` part is a fixed prefix to make it easy to identify session handles.
The ``<key>`` is the Redis key under which the encrypted session is stored.
The ``<secret>`` is an opaque value used to prove that the holder of the session handle is allowed to use it.
Checking the secret prevents someone who can list the keys in the Redis session store from using those keys as session handles.

Session storage
===============

Currently, the only supported backend for session storage is Redis.
Sessions are stored under a Redis key of ``session:<key>`` where ``<key>`` is the session key from the session handle.
The value is JSON encrypted with :py:class:`~cryptography.fernet.Fernet`.
The decrypted session has the following keys:

``secret``
    The session secret, matching the ``<secret>`` portion of the session handle.

``token``
    The full JWT for this authentication session.

``email``
    The email of the user represented by this session.
    Taken from the ``email`` claim of the JWT.

``created_at``
    The time at which the session was created in integer seconds since epoch.

``expires_on``
    The time at which the session will expire in integer seconds since epoch.
    Taken from the ``exp`` claim of the JWT.

The Redis key will be set to expire at the same time represented by ``expires_on``.

User token storage
==================

A user-issued token is also represented by a session, plus some additional information.
An index of all the user-issued tokens for a user is stored in Redis.
Each index entry references a session, which is stored the same way as any other authentication session.
This index is stored as a set under the Redis key ``tokens:<uid>`` where ``<uid>`` is the UID of the user, taken from the claim configured with the ``uid_claim`` configuration parameter (``uidNumber`` by default).
Each index entry is serialized JSON with the following keys:

``key``
    The key of the corresponding session.

``scope``
    The scope of the token stored in that session, taken from the ``scope`` claim.

``expires``
    The expiration of that session in seconds since epoch, taken from the ``exp`` claim.

This index is used primarily to serve the ``/auth/tokens`` page, which allows a user to view and revoke their user-issued tokens.
Expired index entries are only removed when the user visits the ``/auth/tokens`` page.
