# Change log

Versioning follows [semver](https://semver.org/). Versioning assumes that Gafaelfawr is installed and configured via [Phalanx](https://phalanx.lsst.io/), so only changes to configuration changes exposed in the Helm values file are considered breaking changes. The internal configuration format may change in minor releases.

Dependencies are updated to the latest available version during each release. Those changes are not noted here explicitly.

## 7.1.0 (2022-11-29)

### New features

- Gafaelfawr now supports creating `Ingress` resources from `GafaelfawrIngress` custom resources. This provides a more convenient and simpler way of describing the Gafaelfawr configuration and shifts the tedious work of constructing the ingress-nginx annotations to Gafaelfawr, and therefore is the recommended way to create an ingress. The annotation-based configuration method may still be used (and is sometimes needed for ingresses created by third-party charts).

## 7.0.0 (2022-10-27)

### Backwards-incompatible changes

- Creation of `Secret` resources in Kubernetes from `GafaelfawrServiceToken` objects is now done with the [Kopf](https://kopf.readthedocs.io/en/stable/) framework. Sync status is now stored in Kubernetes attributes, and the `status` field of `GafaelfawrServiceToken` objects uses a different format.
- The `gafaelfawr kubernetes-controller` and `gafaelfawr update-service-tokens` commands to manage Kubernetes `Secret` resources containing service tokens have been dropped.

### New features

- While the Kubernetes operator is running, all `Secret` objects created from `GafaelfawrServiceToken` objects are checked for validity every half-hour and replaced if needed.

### Other changes

- Drop types from docstrings where possible and take advantage of the new support in Sphinx for type annotations when rendering internal API documentation. This produces higher-quality output in many cases.

## 6.2.0 (2022-10-13)

### New features

- Groups derived from GitHub organizations and teams can now be specified in the `groupMapping` configuration directly as the organization and team, rather than requiring the administrator first convert that to the internal group name used by Gafaelfawr. This can be used to make the Helm configuration easier to read. There is no change to how Gafaelfawr represents the groups internally or exposes them to applications.
- Group names from the token from an upstream OpenID Connect provider that begin with a slash are normalized to remove the starting slash. This was needed by at least one Keycloak installation.

### Bug fixes

- Fix the `tox -e run` command to start a Gafaelfawr development server. This was broken in 4.0.0.

## 6.1.0 (2022-10-04)

### New features

- Add `--fix` flag to the `gafaelfawr audit` command, which attempts to fix discovered issues where possible. Only some discoverable issues have code to fix them.

### Bug fixes

- If a delegated token is requested from the `/auth` route, the authenticating token now must have a remaining lifetime of at least five minutes or it is treated as if it is expired. This avoids creating delegated tokens with unusably short or zero lifetimes.

### Other changes

- The documentation has been updated and restructured to use the new Rubin user guide theme.

## 6.0.0 (2022-09-27)

### Backwards-incompatible changes

- Remove support for all `X-Auth-Request-*` headers that were not being used. The only available headers are now `X-Auth-Request-Email`, `X-Auth-Request-Token`, and `X-Auth-Request-User`. The other information is already available to the service in other ways (client IP), should not be used by the service due to separation of concerns (scopes), or can be retrieved from the `/auth/api/v1/user-info` or `/auth/api/v1/token-info` routes if required.
- Scopes requested via `delegate_scope` are now optional. If the authenticating token has a scope requested via that parameter, the delegated token will have it, but if it does not, authentication will still succeed and the delegated token will be created, but without that scope. To restore the previous behavior of also requiring that scope for authentication, add it to `scope` as well and either omit `satisfy` or use `satisfy=all`.
- Remove support for a user editing their own tokens, and remove the corresponding UI. This is not a commonly supported operation on tokens in other implementations, such as GitHub. Token administrators with the `admin:token` scope can still edit tokens.
- Drop support for creating InfluxDB tokens, including the configuration options and the `/auth/tokens/influxdb/new` route. This support only worked with InfluxDB 1.x and was not used; InfluxDB 2.x uses an entirely different authentication mechanism.
- The supported URL for getting token information after an OpenID Connect authentication to Gafaelfawr is `/auth/openid/userinfo`. Fix the mistaken creation of `/auth/oidc/userinfo` and drop support for `/auth/userinfo`. The latter incorrectly implies this is a general API, as opposed to specific to the OpenID Connect support.
- Drop support for `/oauth2/callback` as an alias for `/login` and the `config.cilogon.redirectUrl` setting. This was required for some older CILogon integrations at NCSA, but those deployments have been retired.

### New features

- Add new parameter to the `/auth` route, `minimum_lifetime`, which can be used to specify the minimum required lifetime of a delegated token (internal or notebook). If the user's authenticating token doesn't have sufficient remaining lifetime to satisfy this request, `/auth` will return a 401 error to force a reauthentication.
- Add new `gafaelfawr generate-session-secret` command to generate the session secret so that users do not have to write a small script to call the Fernet function.
- Log more details during token creation or modification, including any user identity information stored with the token. Log expiration times in ISO date format instead of seconds since epoch. The names of the attributes logged have changed from previous versions in some cases.
- Log changes to the list of administrators.

### Bug fixes

- Correctly cache empty LDAP group membership results.

### Other changes

- Uvicorn logs are now sent through structlog for consistent JSON formatting. Context expected by Google's Cloud Logging is added to each log message.
- Send `Accept: application/vnd.github+json` instead of `Accept: application/json` when making GitHub API calls.

## 5.2.0 (2022-09-06)

### New features

- The primary GID can now be obtained from the OpenID Connect ID token from either CILogon or generic OpenID Connect by setting `config.cilogon.gidClaim` or `config.oidc.gidClaim`.
- Group membership information coming from OpenID Connect ID tokens no longer has to include GIDs, and may be a simple list of group names rather than a list of dictionaries.
- The name of the claim in an OpenID Connect ID token from which group membership is taken can now be changed by setting `config.cilogon.groupsClaim` or `config.oidc.groupsClaim`.
- Add a Kubernetes `CronJob` to audit Gafaelfawr data stores for inconsistencies and report them to Slack.
- The timing of the maintenance `CronJob` added in 5.1.0 can now be configured with `config.maintenance.maintenanceSchedule` (a cron schedule expression).

### Bug fixes

- Hopefully fix recovery from LDAP connection timeouts by removing a reference to an incorrect exception name, and take advantage of the recovery support in the latest release of [bonsai](https://github.com/noirello/bonsai).

## 5.1.0 (2022-08-18)

### New features

- Add support for synthesizing user private groups. When GitHub is used as the authentication provider, or when LDAP is used as a source of group membership and `config.ldap.addUserGroup` is set to `true`, synthesize an additional group with a name equal to the username and a GID equal to the user's UID and add it to the user's group membership. Be aware that this is not strictly safe for GitHub because the team ID space (used for GIDs) and the user ID space (used for UIDs) are not distinct and may collide (although this is unlikely).
- Add support for a primary GID for a user. When GitHub is used as the authentication provider, this is always set to the same as the UID. For other authentication providers, it can be retrieved from LDAP or, if synthesized user private groups are enabled, will be set to the GID of the user private group. Tokens created by admins can set a GID, which overrides the GID from other sources.
- If configured to get a primary GID for the user from LDAP, and that GID does not appear in the user's group memberships, find the group name corresponding to that GID in the group tree and add it to the user's group memberships. Some LDAP configurations only record explicit memberships for secondary groups and represent the user's primary group only via their GID.
- Add a Kubernetes `CronJob` to delete entries for expired tokens, note their expiration in the token change history, and truncate history tables. History entries older than one year are dropped.
- Add support for configuring a Slack webhook for alerting, and send uncaught exceptions to that webhook if configured.

### Bug fixes

- When a user token was edited to change its scope, but not its expiration time, its scopes were not updated in Redis. Since Redis is canonical for token scopes, this meant that the change appeared to go through but had no actual effect. Fixed by updating Redis if either the scope or expiration of a user token is changed.

## 5.0.2 (2022-07-29)

### Bug fixes

- Improve error handling for LDAP queries. Hopefully Gafaelfawr should now recover automatically from LDAP outages.

### Other changes

- Improve the documentation substantially. Much of the design and implementation information has move to tech notes and the Gafaelfawr documentation references those. The changelog is now maintained in Markdown to ease preparation of GitHub releases.
- Improve logging of exceptions by adding a few more `from` clauses where appropriate.
- Gafaelfawr now uses a pure `pyproject.toml` build system (using the beta support in setuptools) rather than using `setup.cfg` or `setup.py`.

## 5.0.1 (2022-07-21)

### Bug fixes

- Retry LDAP queries after a bonsai `ConnectionError` exception, which may happen due to an intervening firewall timing out the TCP connection.

### Other changes

- Improve logging of exceptions by adding `from` clauses where appropriate to expose the underlying triggering exception.

## 5.0.0 (2022-07-15)

This release overhauls the CILogon and COmanage integration support based on extensive testing. Many of the LDAP configuration options have changed. LDAP connections are now cached and reused.

### Backwards-incompatible changes

- Service tokens now must be for bot users, meaning that the username must begin with `bot-`. This applies to any tokens created via the `/auth/api/v1/tokens` route or via Kubernetes `GafaelfawrServiceToken` resources and the Kubernetes controller.
- Drop support for retrieving the username from LDAP. CILogon can do this automatically and put the username in the OpenID Connect ID token, which was the only use case we had for this functionality. Remove it, and the `config.ldap.usernameBaseDn` and `config.ldap.usernameSearchAttr` Helm parameters, to reduce complexity.
- Add support for getting the full name and email address from LDAP as well. Those plus numeric UID (if configured) now all use `config.ldap.userBaseDn` and `config.ldap.userSearchAttr` to configure how the user's LDAP directory entry is found. Enabling numeric UID lookups now requires setting `config.ldap.uidAttr` plus `config.ldap.userBaseDn`, and `config.ldap.uidBaseDn` is no longer a valid configuration setting.
- Rename `config.ldap.baseDn` to `config.ldap.groupBaseDn` to make it clearer that it is only used for group membership searches.
- Disallow usernames containing only digits, bringing the username policy in sync with [DMTN-225](https://dmtn-225.lsst.io/).

### New features

- The user is now redirected to the enrollment URL, if configured, when the username claim is missing from the upstream OpenID Connect ID token, rather than tying the enrollment URL feature to the (now removed) LDAP lookup of the username.
- LDAP data is cached for up to five minutes to reduce latency and load on the LDAP server.
- Gafaelfawr now uniformly treats data stored with the token as overriding data from external sources, such as LDAP or Firestore. This also applies to tokens created by admins. To create a token but use user data from external sources, omit that data (such as UID or email) in the token creation request.
- Allow data to be missing from LDAP. Users are allowed to not have email addresses or full names.
- Allow users who are not found in LDAP. These will normally be created via the admin token API. User data such as UID, full name, and email address that would normally be retrieved from LDAP (depending on the configuration) will be null instead.
- Add `gafaelfawr delete-all-data` command-line invocation that deletes all data except Firestore UID/GID assignments. This may be useful when performing destructive updates where everyone's usernames may change.
- Use a connection pool for LDAP queries instead of opening a new connection for each query.
- Add `config.oidc.usernameClaim` and `config.oidc.uidClaim` Helm configuration options to customize which claims from the upstream OpenID Connect ID token are used to get the username and UID.

### Bug fixes

- The return status of a successful `PATCH /auth/api/v1/users/<username>/tokens/<token>` request is now 200 instead of 201. Since this modifies a resource rather than creating one, that status code seems more accurate.
- Fix verification of OpenID Connect ID tokens when the upstream issuer URL has a path component. Previous versions of Gafaelfawr would incorrectly look for standard metadata URLs one path level too high.
- Report better errors to the user if Firestore or LDAP fail during login.

## 4.1.0 (2022-04-29)

### New features

- Support assigning UIDs and GIDs using Google Firestore. When this is enabled, UID and GID information from the upstream OpenID Connect provider or from LDAP is ignored, and instead Gafaelfawr assigns UIDs and GIDs to usernames and group names on first use. UIDs and GIDs for usernames and group names will be retrieved from Firestore on initial authentication if already assigned. Currently, OpenID Connect (via CILogon or a generic server) must be used as the authentication provider to use Google Firestore UID and GID assignment.
- Group information from LDAP is now retrieved dynamically when needed instead of stored with an authentication token, so it will change dynamically if the user's groups change in LDAP. This does not affect the token's scopes, only the group information retrieved by a user-info
  API request.
- Support authenticated simple binds to an LDAP server. This requires setting the Helm `config.ldap.userDn` parameter and adding a new `ldap-password` secret.
- Support retrieving the username from LDAP when using an upstream OpenID Connect provider. This is configured with the new `config.ldap.usernameBaseDn` and `config.ldap.usernameSearchAttr` Helm parameters.
- Add an optional enrollment URL configuration when CILogon or generic OpenID Connect is used with LDAP lookups of the username. If this is set and the `sub` claim in the ID token does not resolve to a user entry in LDAP, the user will be redirected to this URL instead of an error page.

### Other changes

- Use the image from the GitHub Container Registry instead of Docker Hub.

## 4.0.0 (2022-03-25)

As of this release, the only supported mechanism for installing Gafaelfawr is as part of the Vera C. Rubin Science Platform, using [Phalanx](https://github.com/lsst-sqre/phalanx/).

### Backward-incompatible changes

- The Gafaelfawr token lifetime is now configured with `config.tokenLifetimeMinutes` instead of `config.issuer.expMinutes`.
- The internal OpenID Connect server now puts the numeric UID in a `uid_number` claim rather than `uidNumber` for consistency with the naming scheme of other claims.
- InfluxDB 1.x token generation is now configured with `config.influxdb.enabled` and `config.influxdb.username` without the `issuer` component.
- Drop support for restricting the upstream OpenID Connect provider to specific key IDs. This prevents upstream key rotation for dubious security benefit given that Gafaelfawr still verifies the issuer URL and then reaches out to its `.well-known` endpoints to retrieve the public key and verify the key signature.

### Bug fixes

- Return 404 with a proper error if the OpenID Connect server routes are accessed when Gafaelfawr is not configured to act as an OpenID Connect server.

### Other changes

- Log token scopes as proper lists instead of space- or comma-separated strings.
- Drop support for Python 3.9.

## 3.6.0 (2022-02-24)

### New features

- Add support for retrieving the user's numeric UID from LDAP when authenticating with an OpenID Connect provider.

### Bug fixes

- Add required dependency for LDAP support to the Docker image.

### Other changes

- Speed up tests somewhat.
- Improve the development documentation.

## 3.5.1 (2022-01-14)

### Bug fixes

- Fix several bugs in Kubernetes GafaelfawrServiceToken object handling that prevented correct creation of Secrets. Work around a bug in kubernetes_asyncio with patching custom objects.

## 3.5.0 (2022-01-13)

### New features

- Add support for obtaining group membership information from LDAP. Currently, this can only be used in conjunction with the OpenID Connect authentication provider.
- Add Helm chart support for using a generic OpenID Connect provider for authentication.

## 3.4.1 (2021-12-09)

### Bug fixes

- Fix database initialization with `gafaelfawr init`, which is also run on pod startup.

## 3.4.0 (2021-12-02)

### New features

- Gafaelfawr now uses async SQLAlchemy for all database calls, which avoids latency affecting the whole process when a request requires database queries or writes.

### Bug fixes

- Internal and notebook tokens are now acquired, when needed, while holding a per-user cache lock. This means that when a flood of requests that all require a delegated token come in at the same time, a given Gafaelfawr process allows only the first request to proceed and blocks the rest until it completes. All the other requests are then served from the cache. This fixes a deadlock observed in previous versions of Gafaelfawr under heavy load from a single user who does not have a cached delegated token.

## 3.3.0 (2021-11-11)

### Other changes

- The Docker image now starts a single async Python process rather than running multiple processes using Gunicorn. This follows the FastAPI upstream recommendations for services running under Kubernetes. Scaling in Kubernetes is better-handled by spawning multiple pods rather than running multiple frontend processes in each pod.
- Update the base Docker image to Debian bullseye and Python 3.9.
- Require Python 3.9 or later.

## 3.2.1 (2021-08-24)

### Bug fixes

- Catch exceptions in the custom resource background thread. Retry up to ten times for Kubernetes exceptions, and crash the entire process on unknown exceptions or more than ten consecutive Kubernetes failures. This prevents a problem where the token update pod continues running and appears to be healthy, but the watcher thread has crashed so it's doing nothing.

### Other changes

- Switch to aioredis 2.0. Unfortuantely, this breaks mockaioredis, so only the Docker tests (which use a real Redis server) can be run for the time being.

## 3.2.0 (2021-07-14)

### Backward-incompatible changes

- HTTP headers are not guaranteed to support character sets other than ASCII, and Starlette forces them to ISO 8859-1. This interferes with correctly passing the user's full name to protected services via HTTP headers. Therefore, drop support for sending the user's full name via `X-Auth-Request-Name`. The name can still be retrieved from the `/auth/api/v1/user-info` API endpoint.

### New features

- Return HTML errors from login failures instead of JSON. The HTML is currently entirely unstyled. Add a new Helm configuration option, `config.errorFooter`, that is included in the HTML of any error message that is shown.
- Fail authentication and show an error if the user is not a member of any of the groups configured in `config.groupMapping`.
- Revoke the GitHub OAuth authorization if the login fails due to no known groups or an invalid username, since in both cases we want to force GitHub to redo the attribute release.

## 3.1.0 (2021-07-06)

### New features

- On explicit logout (via `/logout`), revoke the OAuth authorization for the user if they authenticated with GitHub. This forces a re-release of attributes on subsequent authentication, which will make it easier for users to resolve problems with incorrect attribute releases (if, for instance, they attempted to log in before their team membership was complete).

### Bug fixes

- Correctly handle paginated replies from GitHub for the team membership of a user.
- Fix sorting of tokens retrieved from the admin API to sort by created date before token string.

### Other changes

- Depend on Safir 2.x and drop remaining aiohttp dependency paths. Remove code that is now supplied by Safir. Share one `httpx.AsyncClient` across all requests and close it when Gafaelfawr is shut down.

## 3.0.3 (2021-06-17)

### Bug fixes

- Fix errors when returning existing internal or notebook tokens when two tokens were created for the same parent token due to a race between workers. In previous versions, Gafaelfawr would fail with an exception if there were more than one matching notebook or internal token for a given set of parameters.

## 3.0.2 (2021-06-15)

### Bug fixes

- Display expired tokens as expired in the UI instead of showing the delta of the expiration from the current time.
- Sort token lists in the UI in descending order by last used (not yet populated), then creation date, and only then by the token key.

### Other changes

- Add a timestamp to all log messages, since not all Kubernetes log viewers show the timestamp added by Kubernetes.

## 3.0.1 (2021-06-07)

### Bug fixes

- Display the token key and token type when showing token change history. Since the change history includes subtokens, not showing the type or key was confusing.
- Initialize the database if needed as part of Gafaelfawr container startup.

### Other changes

- Add additional startup logging at the DEBUG level.
- Improve error reporting if Gafaelfawr is unable to connect to its database.

## 3.0.0 (2021-05-18)

This release replaces the Kubernetes secret management approach released with 2.0.0 with a new approach based on a `GafaelfawrServiceToken` custom resource definition. The old configuration-based approach is no longer supported.

### Backward-incompatible changes

- Change `update-service-tokens` to use the custom resource approach instead of configuration plus labeled Kubernetes `Secret` objects.

### New features

- Add new `kubernetes-controller` invocation, which reconciles all `GafaelfawrServiceToken` objects and then starts a watcher and processes new updates as they happen.
- Use local Kubernetes configuration for Kubernetes operations if invoked outside of a Kubernetes cluster.

### Bug fixes

- Increase the timeout for outbound HTTP calls to authentication providers to 20 seconds. Some authentication providers and some Kubernetes cluster networking environments can be surprisingly slow.

## 2.0.1 (2021-04-26)

### Bug fixes

- Cap workers spawned by the Docker image at 10. The defaults spawned 32 workers in a GKE container, which overwhelmed the available open connections with a micro Cloud SQL server.

## 2.0.0 (2021-04-23)

As of this release, Gafaelfawr now uses opaque tokens for all internal authentication and only issues JWTs as part of its OpenID Connect server support. All existing sessions and tokens will be invalidated by this upgrade and all users will have to reauthenticate.

Gafaelfawr now requires a SQL database. Its URL must be set as the `config.databaseUrl` Helm chart parameter.

As of this release, Gafaelfawr now uses FastAPI instead of aiohttp. OpenAPI documentation is available via the `/auth/docs` and `/auth/redoc` routes.

### Backward-incompatible changes

- Eliminate internal JWTs, including the old session and session handle system, in favor of opaque tokens.
- Replace the `/auth/tokens` UI with a new UI using React and Gatsby. Currently, it supports viewing all the tokens for a user, creating and editing user tokens, revoking tokens, viewing token information with the token change history, and searching the token change history.
- protected services no longer receive a copy of the user's authentication token. They must request a delegated token if they want one.
- Enforce constraints on valid usernames matching GitHub's constraints, except without allowing capital letters.
- Only document and support installing Gafaelfawr via the Helm chart.

### New features

- Add a new token API under `/auth/api/v1` for creating, modifying, viewing, and deleting tokens. This is the basis of the new token management UI. API documentation is published under `/auth/docs` and `/auth/redoc`.
- Add support for several classes of tokens for different purposes. Add additional token metadata to record the purpose of a token.
- Add caching of internal and notebook tokens. Issue new internal and notebook tokens when the previous token is half-expired.
- Add support for a bootstrap token that can be used to dynamically create other tokens or configure administrators.
- Add support for maintaining Kubernetes secrets containing Gafaelfawr service tokens for services that need to make authenticated calls on their own behalf.
- The `/auth` route now supports requesting a notebook or internal delegated token for the service.
- Add `/.well-known/openid-configuration` route to provide metadata about the internal OpenID Connect server. This follows the OpenID Connect Discovery 1.0 specification.

### Bug fixes

- Be more careful in interpreting `isMemberOf` claims from the upstream OpenID Connect provider and discard more invalid data.

### Other changes

- Use FastAPI instead of aiohttp, and use httpx to make internal requests.

## 1.5.0 (2020-09-16)

This release fixes some issues with the InfluxDB token issuance support.

### New features

- Add a new configuration option, `issuer.influxdb_username`, and a new Helm chart parameter, `issuer.influxdb.username`, to force the username field of all issued InfluxDB tokens to a single value. This is useful if one does not want to do user management in InfluxDB and is content with granting all users access to a generic account.

### Bug fixes

- Put the username in the `username` field of InfluxDB tokens, not``sub`.

## 1.4.1 (2020-09-11)

This release fixes some bugs in the internal OpenID Connect support uncovered by testing with Chronograf.

### Bug fixes

- Fix data type of the `expires_in` data element returned by the `/auth/openid/token` endpoint. Expiration time in seconds must be truncated to an integer per the relevant standard.
- Fix encoding of the internal JWKS. The relevant standard requires the padding be omitted from the end of the encoding.

## 1.4.0 (2020-08-13)

This release adds a minimalist OpenID Connect server to support protected services that only understand OpenID Connect. The initial implementation is intended to support [Chronograf](https://www.influxdata.com/time-series-platform/chronograf/). Other applications may or may not work. It also adds optional support for issuing InfluxDB authentication tokens.

### New features

- Add support for a password-protected Redis backend. This uses a new configuration parameter, `redis_password_file`, which points to a file containing the password for Redis.
- Add a minimalist OpenID Connect server. The secrets for client connections are read from a file designed by a new configuration parameter, `oidc_server_secrets_file`. The authentication endpoint is `/auth/openid/login` and the token endpoint is `/auth/openid/token`.
- Add a user information endpoint (`/auth/userinfo`) that accepts a JWT and returns its claims. Intended primarily for use with OpenID Connect.
- Add support for issuing InfluxDB authentication tokens via a new `/auth/tokens/influxdb/new` route. InfluxDB requires JWTs with the HS256 algorithm and a shared secret. This feature is enabled by configuring the shared secret via the `issuer.influxdb_secret_file` configuration option.

## 1.3.2 (2020-06-08)

### Bug fixes

- Work around an NGINX ingress bug in 1.39.1 by allowing multiple `X-Forwarded-Proto` headers in the incoming request.

### Other changes

- Document how to configure NGINX ingress with the official Helm chart to support logging accurate client IPs.

## 1.3.1 (2020-05-29)

This release drops support for Python 3.7. Python 3.8 or later is now required.

### New features

- Set the `X-Auth-Request-Client-Ip` header to the calculated client IP on a successful reply from the `/auth` route.
- The output from the `/auth/analyze` route is now sorted and formatted to be easier for humans to read and compare.

### Other changes

- Require Python 3.8 and drop Python 3.7 support.
- Include `token_source` in logs of the `/auth` route to record how the client passed in the authentication token.
- Include more information in the user-facing error message when a connection to the authentication provider's callback endpoint fails.
- Report a better error message if the OpenID Connect provider doesn't have a JWKS entry for the key ID of the identity token.

## 1.3.0 (2020-05-19)

This release changes the construction of identity and groups from GitHub authentication by coercing identifiers to lowercase. GitHub is case-preserving but case-insensitive, which is complex for protected services to deal with. This change ensures Gafaelfawr exposes a consistent canonical identity to downstream services that is also compatible with other systems that expect lowercase identifiers, such as Kubernetes namespaces.

### Backward-incompatible changes

- Lowercase GitHub usernames when constructing identity tokens.
- Lowercase GitHub organization names when constructing group membership.

## 1.2.1 (2020-05-14)

Gafaelfawr can now analyze the `X-Forwarded-For` header to determine the true client IP for logging purposes. This requires some configuration of both Gafaelfawr and the NGINX ingress. See [the logging documentation](https://gafaelfawr.lsst.io/user-guide/prerequisites.html#client-ips) for more information.

### New features

- Add new `proxies` setting to configure what network blocks should be treated as internal to the Kubernetes cluster.
- Set the client IP to the right-most IP in `X-Forwarded-For` that is not in a network block listed in `proxies`.
- Document the necessary NGINX ingress configuration for `X-Forwarded-For` analysis to work correctly.

### Other changes

- Fall back on logging `X-Original-URL` if `X-Original-URI` is not set.
- Stop recommending setting the `auth-request-redirect` annotation and do recommend setting the `auth-method` annotation.

## 1.2.0 (2020-05-07)

New in this release is an `/auth/forbidden` route that can be used to provide a non-cached 403 error page. See [the documentation](https://gafaelfawr.lsst.io/user-guide/gafaelfawringress.html#disabling-error-caching) for more information.

This release changes Gafaelfawr's logging format and standardizes the contents of the logs. All logs are now in JSON. See [the new logging documentation](https://gafaelfawr.lsst.io/user-guide/logging.html) for more information.

### New features

- Default to JSON logging (controlled via `SAFIR_PROFILE`)
- Add remote IP and `User-Agent` header field values to all logs.
- Add more structured information to authentication logging.
- Ensure each route logs at least one event.

## 1.1.1 (2020-04-29)

### Bug fixes

- Include any errors from the external OpenID Connect provider in the error message if retrieving an ID token fails. Previous versions only reported a generic error message, which was missing error details from the JSON body of the upstream error, if available.

## 1.1.0 (2020-04-28)

This release overhauls configuration parsing and removes use of Dynaconf. As a result, the top-level environment key in configuration files is no longer required (or supported). All configuration settings should now be at the top level.

This release also adds support for specifying the type of authentication challenges to unauthenticated users.

### Backward-incompatible changes

- Replace Dyanconf with pydantic for configuration parsing. This should produce much better diagnostics for invalid configuration files. This also eliminates the Dynaconf environment key that was previously expected to be the top-level key of the configuration file. Existing configuration files will need to be flattened by removing that key and elevating configuration settings to the top level.

### New features

- Add support for an `auth_type` parameter to the `/auth` route. This can be set to `basic` to request that unauthenticated users be challenged for Basic authentication instead of Bearer. That in turn will cause pop-up authentication prompting in a web browser.
- Fix syntax of `WWW-Authenticate` challenges and return them in more cases. Attempt to properly implement RFC 6750, including using proper `error` attributes, including challenges in some 400 and 403 replies, and including the `scope` attribute where appropriate.
- Return 403 instead of 401 for unauthenticated AJAX requests. 401 triggers the redirect handling in ingress-nginx, but this is pointless for AJAX requests, which cannot navigate the redirect to an external authentication provider. Worse, AJAX requests may be frequently retried on error (such as an expired credential), which if redirected can create a low-grade denial of service attack on the authentication provider, trigger rate limiting, and cause other issues. AJAX requests, as detected by `X-Requested-With: XMLHttpRequest` in the request headers, now get a 403 reply if they have missing or expired credentials.

## 1.0.0 (2020-04-24)

JWT Authorizer has been renamed to Gafaelfawr. It is named for Glewlwyd Gafaelfawr, the knight who challenges King Arthur in *Pa gur yv y porthaur?* and, in later stories, is a member of his court and acts as gatekeeper. Gafaelfawr is pronounced (very roughly) gah-VILE-vahwr.

As of this release, Gafaelfawr supports OpenID Connect directly and no longer uses oauth2_proxy. There are new options to configure the OpenID Connect support.

The configuration has been substantially overhauled in this release and many configuration options have changed names. Please review the documentation thoroughly before upgrading.

### Backward-incompatible changes

- The `/auth` route now takes a `scope` parameter instead of a `capability` parameter to specify the scopes required for authorization.
- Rename `Capability` to `Scope` in the headers exposed after successful authorization.
- Overhaul how authentication sessions and user-issued tokens are stored in Redis. This will invalidate all existing sessions and user-issued tokens on upgrade. Sessions are now encrypted with Fernet rather than with the complex encryption required for oauth2_proxy compatibility.
- Significantly overhaul the configuration settings. Delete the unused configuration options `www_authenticate`, `no_authorize`, `no_verify`, and `set_user_headers`. Eliminate the `issuers` setting in favor of configuring the upstream issuer in the OpenID Connect configuration. Rename the configuration settings for the internal issuer.
- Require that all tokens have claims for the username and UID (the claim names are configurable).
- Drop support for reading tokens from `X-Forwarded-Access-Token` or `X-Forwarded-Ticket-Id-Token` headers.
- Protect against open redirects in the `/login` route. The destination URL now must be at the same host as the `/login` route.
- Remove support for configuring secrets directly and only read them from files. It simplifies the code and improves testing to have only one mechanism of secret management.

### New features

- Add native support for OpenID Connect.
- Always set the `scope` claim when issuing internal tokens, based on group membership, and only check the `scope` claim during authorization.
- Add a new `/logout` route.
- Add `/oauth2/callback` as an alias for the `/login` route for backwards compatibility with oauth2_proxy deployments.
- Add the `generate-key` CLI command to ease generation of a new signing key.

### Bug fixes

- Fix a security weakness where a user could request a token with any known scope, regardless of the scopes of their own authentication token. The scopes of user-issued tokens are now limited to the scopes of the token used to authenticate to the token creation page.
- Cleanly shut down Redis connections when shutting down the server.

### Other changes

- Rename the application to Gafaelfawr and the Python package to gafaelfawr.
- Simplify token verification for internally-issued tokens and avoid needless HTTP requests to the JWKS route.
- Improve logging somewhat (although it's still not structured or documented).
- Add architecture documentation and a glossary of terms to the manual.
- Flesh out the Kubernetes installation documentation and document the standard Helm chart.

## 0.3.0 (2020-04-20)

With this release, JWT Authorizer has been rewritten to use aiohttp instead of Flask. There are corresponding substantial changes to how the application is started, which are reflected in the Docker configuration. A new configuration key, `session_secret` is now required and is used to encrypt the session cookie (replacing `flask_secret`).

### Backward-incompatible changes

- Remove support for authorization plugins and always do authorization based on groups. None of the Rubin Observatory configurations were using this support, and it allows significant code simplification.
- Remove some unused configuration options.

### New features

- Add support for GitHub authentication. This is done via a new `/login` route and support for authentication credentials stored in a cookie.
- Add a (partial) manual. The formatted text is published at [gafaelfawr.lsst.io](https://gafaelfawr.lsst.io). Included are partial installation instructions, a guide to configuration settings, and API documentation.
- Add support for serving `/.well-known/jwks.json` for the internal token signing key, based on the configured private key. A separate static web service is no longer required.
- Allow GET requests to `/analyze` and return an analysis of the user's regular authentication token.

### Other changes

- Rewrite using aiohttp and aioredis instead of Flask and redis.
- Trust `X-Forwarded-For` headers (primarily for logging purposes).
- Add improved example configuration files in `example`.
- Significantly restructure the code to hopefully make the code more maintainable.
- Significantly expand the test suite.
- Support (and test) Python 3.8.
- Change the license to MIT from GPLv3.

## 0.2.2 (2020-03-19)

### Bug fixes

- Fix decoding of dates in the `oauth2_proxy` session.

## 0.2.1 (2020-03-18)

### Bug fixes

- Fix misplaced parameter when decoding tokens in the `/auth` route.

## 0.2.0 (2020-03-16)

### New features

- Add `/auth/analyze` route that takes a token or ticket via the `token` POST parameter and returns a JSON analysis of its contents.

### Other changes

- Overhaul the build system to match other SQuaRE packages.
