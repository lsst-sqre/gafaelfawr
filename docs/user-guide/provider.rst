#######################
Authentication provider
#######################

.. _github-config:

GitHub
------

If you will be using GitHub as the authentication provider, you will need to create a GitHub OAuth app for Gafaelfawr and obtain a client ID and secret.
To get these values, go to Settings → Developer Settings for either a GitHub user or an organization, go into OAuth Apps, and create a new application.
The callback URL should be the ``/login`` route under the hostname you will use for your Gafaelfawr deployment.

.. _cilogon-config:

CILogon
-------

If you will use CILogon as the authentication provider, you will need to register with CILogon to get a client ID and secret.

Normally, CILogon is used in conjunction with COmanage, and Gafaelfawr should be registered as a OIDC client in the settings of the corresponding COmanage instance.
For details on how to do this, see SQR-055_.

.. _SQR-055: https://sqr-055.lsst.io/

Other OpenID Connect provider
-----------------------------

Gafaelfawr supports client authentication using an arbitrary OpenID Connect provider, as long as the provider supports a ``response_type`` of ``code``, a ``grant_type`` of ``authorization_code``, accepts a ``client_secret`` for authentication, and returns tokens that contain a username and numeric UID.
You will need the following information from the OpenID Connect provider:

- Client ID that Gafaelfawr will use to authenticate
- Client secret corresponding to that client ID
- JWT audience corresponding to that client ID
- Authorization endpoint URL (where the user is sent to authorize Gafaelafwr)
- Token endpoint URL (from which Gafaelfawr retrieves a token after authentication)
- JWT issuer URL
- List of scopes to request from the OpenID Connect provider
