#############
User metadata
#############

User metadata is supplemental information about a user, specifically their name, email address, UID, primary GID, and group membership.
Gafaelfawr can obtain this information from several sources, depending on its configuration.

Conceptually, user metadata is associated with the username and is the same across all of their tokens.
Operationally, metadata from GitHub and from admin token requests is stored in the token, so Gafaelfawr starts from a token and its associated data when determining user metadata.

UID
===

The UID is determined as follows.

#. If the token was created by an admin request that specified a UID, or is the child token of a token with an associated UID, return that UID.
#. If Firestore support is configured, allocate a UID from Firestore if necessary and return the UID in Firestore.
#. If the token was created from a GitHub authentication, return the GitHub user ID as the UID.
#. If LDAP is configured and the ``uidAttr`` setting is not null, search LDAP for the user's UID using the configured LDAP attribute.

If the algorithm falls off the end of this list, Gafaelfawr is misconfigured or the data is missing from LDAP.
Return an error.

Primary GID
===========

The primary GID is determined as follows.
Note that the UID must be determined first.

#. If the token was created by an admin request that specified a GID, or is the child token of a token with an associated GID, return that GID.
#. If the authentication mechanism is GitHub, return the UID as the primary GID.
#. If LDAP is configured and the ``gidAttr`` setting is not null, search LDAP for the user's primary GID using the configured LDAP attribute.
#. If ``addUserGroup`` is enabled, search the LDAP group tree for a group whose name matches the username, and use the GID of that group as the primary GID.
#. Return `None` as the primary GID.

Gafaelfawr does not require users have a primary GID.
Bot users often do not, for example.
Some services, such as `Nublado <https://nublado.lsst.io/>`__, may reject users who do not have a primary GID, however.
