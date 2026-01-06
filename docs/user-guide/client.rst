:og:description: Learn how to use the Gafaelfawr Python client.

.. py:currentmodule:: rubin.gafaelfawr

########################
Gafaelfawr Python client
########################

Any service protected by Gafaelfawr will get some basic information about authenticated requests in the headers of each incoming request.
See :ref:`auth-headers` for more information.

Some services need to know additional information about the user, such as their UID and GID, group membership, or quota.
Services written in Python should use the Gafaelfawr Python client, `rubin.gafaelfawr`.
This library is available from PyPI and can be declared as a dependency or installed with pip in the normal way:

.. prompt:: bash

   pip install rubin-gafaelfawr

Consumers in other languages, such as JavaScript, can use the Gafaelfawr server API directly.

Creating a client
=================

Use the FastAPI dependency
--------------------------

If the client is a FastAPI application, it's usually easiest to use the provided FastAPI dependency.
This maintains a singleton process-global Gafaelfawr client that shares an HTTP connection pool with the Safir `~safir.dependencies.http_client.http_client_dependency` and a Repertoire client with `~rubin.repertoire.discovery_dependency`.

To use this dependency, no initialization is required.
Simply import it and include it in the parameters to whatever route needs to make Gafaelfawr client calls:

.. code-block:: python

   from fastapi import Depends, Header
   from rubin.gafaelfawr import GafaelfawrClient, gafaelfawr_dependency
   from typing import Annotated


   @router.get("/something")
   async def handle_something(
       dataset: str,
       *,
       gafaelfawr: Annotated[GafaelfawrClient, Depends(gafaelfawr_dependency)],
       x_auth_request_token: Annotated[str, Header()],
   ) -> SomeModel:
       userinfo = await gafaelfawr.get_user_info(x_auth_request_token)
       # ...do something with the information...

This dependency uses `~safir.dependencies.http_client.http_client_dependency` under the hood, so you should insert a call to ``http_client_depnedency.aclose()`` in the cleanup portion of your application's FastAPI lifespan callback.
See `the Safir documentation <https://safir.lsst.io/user-guide/http-client.html>`__ for more details.

Manually creating a client
--------------------------

Other users can create a Gafaelfawr client by calling the `GafaelfawrClient` constructor.
Normally, no parameters are needed.
Call `GafaelfawrClient.aclose` to shut down its internal HTTPX_ connection pool when the client is no longer used.

If the application has an existing HTTPX_ connection pool, that ``httpx.AsyncClient`` object can be passed in as the first argument and the Gafaelfawr client will use that.

The Gafaelfawr client uses Repertoire_ under the hood to discover the location of Gafaelfawr.
This means that Repertoire must also be configured, which normally means that the ``REPERTOIRE_BASE_URL`` environment variable must be set.
See the `Repertoire documentation <https://repertoire.lsst.io/user-guide/initialization.html>`__ for more information.
If the application has an existing Repertoire client, that client can be passed to `GafaelfawrClient` as the ``discovery_client`` parameter to save some internal resource duplication.

Additional parameters allow the client to optionally tweak the internal cache parameters or change the structlog_ logger.
See the `GafaelfawrClient` API documentation for all of the details.

Getting user information
========================

Some applications need additional information about a user beyond the small amount of information that Gafaelfawr adds to the incoming request headers (see :ref:`auth-headers`).
There are two ways to request user information: with a delegated token, or by using a privileged service token.

.. warning::

   Depending on the Gafaelfawr configuration and the type of user, much or even all of the user information may be missing.
   If the application requires specific information, such as UID and GID, it should be prepared to return an error to the user if that information is not available.

   No application should rely on getting the user's full name or email address unless the application knows this is guaranteed by the local identity management configuration.
   In many Gafaelfawr configurations, these fields will be `None` for most or all users.

Getting user information with a delegated token
-----------------------------------------------

Applications protected by Gafaelfawr can request a delegated token to act on behalf of the user (see :ref:`delegated-tokens`).
Requesting such a token and then using it to request user information from Gafaelfawr is the preferred and most common way to get user information.
Tokens used for this purpose do not require any scopes.
The application may still need to request some delegated scopes if it will also use the token to make requests to other services on behalf of the user.

To get user information from a delegated token, pass that token as the argument to `GafaelfawrClient.get_user_info`.
The return value will be a `GafaelfawrUserInfo` object, which will contain all the information Gafaelfawr knows about the user.

Getting user information with a service token
---------------------------------------------

Some applications are not in a position to get a token for the user but still need information about the user, such as their quota.
This happens sometimes in backend processing services that do work that is not directly associated with a specific HTTP request from a user.

To obtain user information without having a token for the user, the application must have a token with ``admin:userinfo`` scope.
Usually, it will obtain this token via a ``GafaelfawrServiceToken`` Kubernetes object (see :doc:`service-tokens`).

Then, call `GafaelfawrClient.get_user_info`, passing in both that service token and, as the second argument, the username for which to get information.
The result will be a `GafaelfawrUserInfo` object.

Be aware that some Gafaelfawr configurations will raise `GafaelfawrNotFoundError` for any request for user information with a service token.
This is the case for GitHub configurations, for example.
`GafaelfawrNotFoundError` may also be raised in some cases when requesting user information for service tokens.
Applications calling this method usually will want to catch that exception, as well as be prepared for missing data as discussed above.

Caching
-------

By default, the last 1000 responses will be cached for up to five minutes.
The cache parameters can be tuned in the `GafaelfawrClient` constructor.
There are separate caches for retrieving user information by token and by username (but most applications will only use one or the other call pattern).

To clear the cache and force any subsequent requests to go back to the Gafealfawr API, call `GafaelfawrClient.clear_cache`.

Creating service tokens
=======================

To create a new service token, call `GafaelfawrClient.create_service_token`.
The authentication token, passed as the first argument, must have ``admin:token`` scope.
The username for which the service token is being created must begin with ``bot-``.

The user information provided to the `~GafaelfawrClient.create_service_token` call is stored with the token and overrides other user information sources.
If these fields (``name``, ``uid``, ``gid``, and ``groups``) are not specified, they will be retrieved from the default configured Gafaelfawr user information source, which may be :ref:`LDAP <ldap-user>` or :ref:`Firestore <firestore>` depending on the configuration.
In environments without LDAP, or environments where bot users are not present in LDAP (which is common), this information will be blank (`None`) in the user information for that token unless it is provided at token creation time.
