# Change log

Gafaelfawr is versioned with [semver](https://semver.org/). Changes to metrics and logging are not considered backwards-incompatible changes.

Dependencies are updated to the latest available version during each release. Those changes are not noted here explicitly.

Find changes for the upcoming release in the project's [changelog.d directory](https://github.com/lsst-sqre/gafaelfawr/tree/main/changelog.d/).

Gafaelfawr does not support direct upgrades from versions older than 10.0.0. When upgrading from an older version, first upgrade to a version of Gafaelfawr between 10.0.0 and 12.1.0, inclusive, and complete the schema migration. Then you can safely upgrade to the latest version.

<!-- scriv-insert-here -->

<a id='changelog-12.5.1'></a>
## 12.5.1 (2025-02-10)

### Bug fixes

- Escape the Redis passsword when constructing a URL for the limits library.

<a id='changelog-12.5.0'></a>
## 12.5.0 (2025-02-05)

### New features

- Treat an API quota of 0 as an administrative block and return a 403 error instead of a 429 error. This allows quotas to be used as an emergency way to block access to a specific service without changing scopes.
- Include information on total quota and requests within the current window in `auth_user` and `auth_bot` metrics events if the request was subject to an API quota.
- Record a `rate_limit` metrics event when a request is rejected due to API rate limits.

### Bug fixes

- Allow any authenticated user to see the current quota overrides, rather than restricting them to admins. Changing the quota overrides still requires an admin scope.

### Other changes

- Include the name of the service, if known, in authorization log messages.
- Include API quota information in the log messages for successful authorization if an API quota applies.
- Log the successful authorization message after any messages about creating new notebook or internal tokens, reflecting the true order of operations.
- Log requests rejected due to rate limiting.

<a id='changelog-12.4.0'></a>
## 12.4.0 (2025-01-22)

### New features

- API rate limits are now enforced if configured. If a request exceeds the rate limit, Gafaelfawr will return a 429 response with a `Retry-After` header. Rate limit data is recorded in the new ephemeral Redis pool.
- Add support for quota overrides. Overrides can be set via a new REST API at `/auth/api/v1/quota-overrides` and take precedence over the configured quotas if present and applicable.
- Add a `bypass` key to the quota configuration containing a group list. Any member of one of those groups ignores all quota restrictions.
- Add a flag to notebook quotas, defaulting to true, that indicates whether the user is allowed to spawn a new lab. This is not enforced by Gafaelfawr; it will be read and acted on by [Nublado](https://nublado.lsst.io).

### Bug fixes

- If the user returns to the login route without login state and no return URL is set (which will be the common case), redirect them to the after logout URL instead of returning a 403 error. Often this means the user previously authenticated via another tab and is now logged on, but we have lost the return URL and do not know where to send them. Returning the error is more confusing and often causes the user to attempt to reload the error page, which then fails.

### Other changes

- OpenID Connect authentication codes are now stored in an ephemeral Redis instance rather than in the same database as data, such as tokens, that should persist.

<a id='changelog-12.3.2'></a>
## 12.3.2 (2025-01-09)

### Bug fixes

- Pass multiple delegate scopes to the `/auth` route by repeating the `delegate_scope` query parameter instead of passing a comma-separated list as a single value. ingress-nginx 4.12.0 no longer allows `%` in the `auth-url` annotation and `,` was not initially allowed, and this matches how `scope` was handled.

<a id='changelog-12.3.1'></a>
## 12.3.1 (2025-01-08)

### Bug fixes

- Do not escape `:` characters in the `auth-url` `Ingress` annotation. ingress-nginx 4.12.0 has added a restrictive regex filter to acceptable URLs that disallows `%` and therefore all escaped characters.

<a id='changelog-12.3.0'></a>
## 12.3.0 (2024-12-11)

### New features

- Allow an authenticated `GafaelfawrIngress` with no required scopes. This is useful for an `onlyService` case where the token may have any scope but must be delegated to one of the listed services.

### Bug fixes

- Return a JSON-serializable object from the health probe for the Kubernetes operator.

<a id='changelog-12.2.0'></a>
## 12.2.0 (2024-11-26)

### New features

- Allow a client to present an internal token to the `/auth/openid/userinfo` endpoint. CADC's authenticator finds the userinfo endpoint via OpenID Connect configuration and presents whatever token it has to that endpoint, so this allows it to use the regular userinfo endpoint.
- Add optional [Sentry](https://sentry.io/welcome/) support. If enabled and configured with the Sentry DSN secret, telemetry information will be sent to Sentry. Every trace is sampled and no effort has been made to exclude sensitive information, so this is currently only intended to be temporarily enabled in a non-production environment while debugging a specific problem.

### Bug fixes

- Avoid opening a database session in the ingress authentication path unless it is necessary to create a new delegated token.
- Avoid creating a Google Firestore client for every request, since it does authentication setup on creation. Instead, create a single client that will be used for all requests.
- Always omit the `data_rights` claim in OpenID Connect server tokens if the user has no data rights, rather than sometimes omitting it and sometimes setting it to the empty string.

### Other changes

- Update the Gafaelfawr secrets documentation with a link to the current Phalanx secrets management documentation and mark the secrets that are autogenerated by Phalanx tooling.

<a id='changelog-12.1.1'></a>
## 12.1.1 (2024-11-19)

### Bug fixes

- Avoid double slashes in the endpoint URLs returned by `/.well-known/openid-configuration`, fixing a bug introduced in Gafaelfawr 12.0.0.

### Other changes

- Gafaelfawr no longer supports direct upgrades from versions older than 10.0.0. When upgrading from an older version, upgrade to 12.1.0 or earlier first and complete the database schema migration, and then upgrade to the latest version.

<a id='changelog-12.1.0'></a>
## 12.1.0 (2024-10-28)

### New features

- Add support for `client_secret_basic` to the token endpoint for the OpenID Connect server. This is the recommended default authentication strategy and some clients don't support negotiating `client_secret_post` instead.
- Add a `config.baseInternalUrl` Helm setting to override Gafaelfawr's understanding of its own internal URL, used when constructing `Ingress` resources from `GafaelfawrIngress`.
- Gafaelfawr now adds the `app.kubernetes.io/managed-by` label with value `Gafaelfawr` to all `Ingress` resources generated from `GafaelfawrIngress` resources.
- Separate `auth` metrics into `auth_bot` and `auth_user` metrics, where the former are authentications to services from bot users and the latter are authentications from non-bot users. Stop excluding mobu bot users now that they can be included in the `auth_bot` metric instead.

<a id='changelog-12.0.1'></a>
## 12.0.1 (2024-10-21)

### Bug fixes

- Fix startup error when metrics reporting is disabled.

<a id='changelog-12.0.0'></a>
## 12.0.0 (2024-10-18)

### Backwards-incompatible changes

- The `/auth` and `/auth/anonymous` routes have moved to `/ingress/auth` and `/ingress/anonymous` and are no longer accessible outside of the cluster. These routes may only be accessed by the ingress controller via cluster-internal URLs. This prevents users from creating arbitrary internal tokens for themselves.
- Drop support and remove documentation for configuring an `Ingress` to use Gafaelfawr rather than using the `GafaelfawrIngress` custom resource.
- The `/ingress/auth` route now requires `X-Original-URL` to be set.
- Since the CADC authentication code no longer requires the `sub` claim be a UUID, set `sub` to the username in the response from `/auth/cadc/userinfo`. This allows the CADC TAP server to store the username in the UWS jobs table.

### New features

- Add support for exporting metrics to Kafka using the new event metrics support in [Safir](https://safir.lsst.io/). The initial set of events is limited to login metrics, authentications to services, and counts of active sessions and user tokens.
- `GafaelfawrIngress` now accepts a `service` parameter at the top level of the configuration and uses that to tag authentication metrics by service. This corresponds to the `service` query parameter to the `/auth` route. If `delegate_to` is also set (`config.delegate.internal.service` in `GafaelfawrIngress`), it must match the value of `service`. This parameter is currently optional but will eventually become mandatory.
- Add `config.onlyServices` to `GafaelfawrIngress`, which restricts the ingress to tokens issued to one of the listed services in addition to the other constraints.
- If a request is authenticated with an internal token, include the service associated with that token in an `X-Auth-Request-Service` header passed to the protected service.
- Setting `config.baseUrl` in a `GafaelfawrIngress` resource is no longer required. That value will be used if present, but only for constructing the login URL, not the `/ingress/auth` URL. Instead, a global default is set by the Helm chart. The `config.baseUrl` setting will be removed entirely in a future release.
- Add new command `gafaelfawr generate-schema`, which generates the SQL required to create the Gafaelfawr database schema.

### Bug fixes

- If the user returns from authentication and no longer has login state in their cookie, redirect them to the destination URL without further processing instead of returning an authentication state mismatch error. The most likely cause of this state is that the user authenticated from another browser tab while this authentication is pending, so Gafaelfawr should use their existing token or restart the authentication process.
- Reset login state after an error so that any subsequent authentication attempt will generate a new, random state parameter.
- Stop including the required scopes in 403 errors when the request was rejected by a username restriction rather than a scope restriction, since the client cannot fix this problem by obtaining different scopes.
- Fix an error in configuration validation, introduced in 11.0.0, that caused validation rules to not be applied to any URL or DSN in the Gafaelfawr configuration.
- Cap the Kubernetes operator worker limit at 5 to avoid overwhelming the API server.
- Check that `tokenLifetime` is at least as long as twice the minimum token lifetime.

### Other changes

- Honor the `POSTGRES_5432_TCP_PORT`, `POSTGRES_HOST`, `REDIS_6379_TCP_PORT`, and `REDIS_HOST` environment variables if they are set and override the configured database URL and Redis URL with them. This is required to work with the latest version of tox-docker for testing and development. These environment variables are not used inside a Phalanx deployment.

<a id='changelog-11.1.1'></a>
## 11.1.1 (2024-05-24)

### Bug fixes

- Respect the enrollmentUrl configuration setting when CILogon is the authentication provider, fixing a problem introduced in the 11.0.0 release.
- Detect when someone attempts to mark as admin a username that is already an admin and return a 409 error instead of raising an uncaught exception.
- Return a more-correct 409 HTTP error code, instead of 422, when a user attempts to use a duplicate token name.
- When creating a new token, try to remove it from Redis if the SQL write fails. This will hopefully reduce the number of orphaned tokens created during SQL server or proxy restarts.

<a id='changelog-11.1.0'></a>
## 11.1.0 (2024-05-23)

### New features

- Add new `authCacheDuration` setting to the `GafaelfawrIngress` Kubernetes resource, which tells Gafaelfawr to configure NGINX to cache a Gafaelfawr response for the specified length of time. The cache is invalidated if the `Cookie` or `Authorization` HTTP headers change.

### Bug fixes

- Close database sessions after each execution of a Kopf Kubernetes operator. Previous versions of Gafaelfawr leaked sessions until the Kubernetes operator restarted.

<a id='changelog-11.0.1'></a>
## 11.0.1 (2024-05-21)

### Bug fixes

- Correctly parse the configuration if `quota` is set to an empty object.
- Reject configuration files that assign scopes in `groupMapping` but do not define those scopes in `knownScopes`.

<a id='changelog-11.0.0'></a>
## 11.0.0 (2024-05-20)

### Backwards-incompatible changes

- Drop support for getting user metadata from OpenID Connect token claims. LDAP, for both user metadata and group membership, is now required when using an OpenID Connect authentication, including CILogon.
- Remove support for getting group GIDs from a ForgeRock Identity Management server. LDAP support should be used instead.
- Drop support for LDAP groups without GIDs. Either Firestore GID assignment must be enabled or LDAP must contain a GID for each group. Groups without GIDs in LDAP will be ignored if Firestore is not enabled.
- Retrieval of the UID and primary GID from LDAP is now enabled by default unless Firestore is enabled.
- Replace `config.tokenLifetimeMinutes` with `config.tokenLifetime`, which accepts one or more time intervals with suffixes `w`, `d`, `h`, `m`, and `s` for weeks, days, hours, minutes, and seconds, respectively.
- Change the default of `config.cilogon.usernameClaim` to `username`. This is what we use for all current CILogon integrations.
- Change the default of `config.ldap.groupSearchByDn` to true. To preserve the previous behavior of searching by the bare username, this setting must be explicitly set to false.
- Support for `config.loglevel` in Helm values has been dropped. Use `config.logLevel` instead (note the capital `L`).
- Remove the `/auth/analyze` route. This was an old way for a user to see information about their token that has been deprecated for many releases. The output used the old JWT token claim format and was missing a great deal of useful information. `/auth/api/v1/user-info` and `/auth/api/v1/token-info` should be used instead.

### New features

- Support overriding the HTTP authentication realm for `WWW-Authenticate` challenges by setting `config.realm`.
- Support overriding the OpenID Connect issuer (`iss` claim) and key ID (`kid` claim) for the internal OpenID Connect server by setting `config.oidcServer.issuer` and `config.oidcServer.kid`, respectively.

### Other changes

- Drop support for running a local development instance of Gafaelfawr. This support wasn't used during development and has some maintenance cost. Integration testing of development versions of Gafaelfawr should instead be done in a development Phalanx environment.
- Move the `docker-compose.yaml` file, now used only for creating Alembic migrations, into the `alembic` subdirectory and update the documentation for creating new Alembic migraitons accordingly.

<a id='changelog-10.1.0'></a>
## 10.1.0 (2024-03-15)

### New features

- Add a health check internal route, `/health`, which is available only inside the Kubernetes cluster. Check that the database, Redis, and (if configured) LDAP and Firestore connections are all working. Use that as a liveness check so that Kubernetes will restart Gafaelfawr if any of those connection pools are no longer working.
- Add a health check for the Kubernetes operator that tests the Kopf infrastructure as well as the database and Redis connections. Use that as a liveness check to restart the operator if the health check starts failing.

### Bug fixes

- Ensure that only one Gafaelfawr operator pod is running at a time.
- Add Kubernetes resource requests and limits for the Cloud SQL Auth Proxy sidecar container.

<a id='changelog-10.0.1'></a>
## 10.0.1 (2024-02-22)

### Bug fixes

- Fix check for current database schema when starting the web application.

<a id='changelog-10.0.0'></a>
## 10.0.0 (2024-02-22)

Upgrading to this version requires a [database schema migration](https://phalanx.lsst.io/applications/gafaelfawr/manage-schema.html).

### Backwards-incompatible changes

- Clients of the Gafaelfawr OpenID Connect server now must have registered return URIs as well as client IDs and secrets. Each element of the `oidc-server-secrets` secret must, in addition to the previous `id` and `secret` keys, contain a `return_uri` key that matches the return URL of authentications from that client. Those return URLs are now allowed to be at any (matching) domain and are not constrained to the same domain as Gafaelfawr.
- When acting as an OpenID Connect server, Gafaelfawr no longer exposes all claims by default. Instead, it now honors the `scope` parameter in the request, which must include `openid` and may include `profile` and `email`.
- In the reply to a successful OpenID Connect authentication, return a Gafaelfawr token of a new `oidc` type as the access token instead of a copy of the ID token. This `oidc` token will be marked as a child token of the underlying Gafaelfawr token used to authenticate the OpenID Connect login, which means it will automatically be revoked if the user logs out.
- Only accept Gafaelfawr tokens of the `oidc` type for the OpenID Connect server userinfo endpoint.
- Return only userinfo claims from the OpenID Connect server userinfo endpoint instead of the full set of claims that would go into an ID token. Currently, the userinfo claims are not filtered based on the requested scopes; all available userinfo claims are returned.
- Set the `aud` claim in OpenID Connect ID tokens issued by Gafaelfawr to the client ID of the requesting client instead of a fixed audience used for all tokens.
- OpenID Connect ID tokens issued by Gafaelfawr now inherit their expiration time from the underlying Gafaelfawr token used as the authentication basis for the ID token. Previously, OpenID Connect ID tokens would receive the full default lifetime even when issued on the basis of Gafaelfawr tokens that were about to expire.
- Require the `oidcServer.issuer` configuration setting use the `https` scheme, since this is required by the OpenID Connect 1.0 specification.

### New features

- Add a new `rubin` scope for the OpenID Connect server that, if requested, provides a `data_rights` claim listing the data releases to which the user has rights. Add a new `config.oidcServer.dataRightsMapping` configuration option that is used to determine that list of data releases from a user's group memberships.
- Add support for a client-supplied nonce in OpenID Connect authentication with Gafaelfawr as a server. The provided nonce is passed through to the ID token following the OpenID Connect specification.
- Check the database schema at startup to ensure that it is current, and refuse to start if the schema is out of date.
- Add new `gafaelfawr update-schema` command that creates the database if necessary and otherwise applies any needed Alembic migrations.
- Add new `gafaelfawr validate-schema` command that exits non-zero if the database has not been initialized or if the schema is not up-to-date.

### Bug fixes

- Include the scope used to issue the ID token in the reply from the OpenID Connect server token endpoint.
- In the response from `/.well-known/openid-configuration`, declare that the only supported response mode of the OpenID Connect server is `query`.

### Other changes

- Gafaelfawr now uses [Alembic](https://alembic.sqlalchemy.org/en/latest/index.html) to perform database migrations as needed.
- Gafaelfawr now uses [uv](https://github.com/astral-sh/uv) to maintain frozen dependencies and set up a development environment.

<a id='changelog-9.6.1'></a>
## 9.6.1 (2023-12-08)

### Bug fixes

- Adjust the Redis connection pool parameters to hopefully improve recovery after a Redis server restart.

<a id='changelog-9.6.0'></a>
## 9.6.0 (2023-12-04)

### New features

- An ingress may now be restricted to a specific user by setting the `username` attribute in the `config` section of a `GafaelfawrIngress`, or the corresponding `username` query parameter to the `/auth` route. Any other user will receive a 403 error. The scope requiremments must also still be met.

### Bug fixes

- Add an ARIA label to the icon for deleting a token in the user interface for better accessibility.

<a id='changelog-9.5.1'></a>
## 9.5.1 (2023-10-30)

### Bug fixes

- Add a socket timeout, enable keepalive, and fix the retry specification for the Redis connection pool to help Gafaelfawr recover from Redis outages.
- Always mask all headers to which Gafaelfawr gives special meaning when passing requests to a service downstream of a `GafaelfawrIngress`, instead of only masking the ones Gafaelfawr might set in that configuration. This ensures that no service behind a `GafaelfawrIngress` sees, e.g., `X-Auth-Request-User` unless it truly is authenticated by Gafaelfawr.

<a id='changelog-9.5.0'></a>
## 9.5.0 (2023-10-25)

### New features

- Add new `/auth/cadc/userinfo` route, which accepts a Gafaelfawr token and returns user metadata in the format expected by the CADC authentication code. This route is expected to be temporary and will be moved into the main token API once we decide how to handle uniqueness of the `sub` claim. It is therefore not currently documented outside of the autogenerated API documentation.
- Gafaelfawr now imposes a maximum run time and retention duration for its periodic maintenance jobs. These can be adjusted with the new `config.maintenance.deadlineSeconds` and `config.maintenance.cleanupSeconds` Helm settings.
- All Gafaelfawr pods now set Kubernetes resource requests and limits. The requests match the consumption of a lightly-loaded deployment using OpenID Connect and LDAP, and the limits should be generous. These can be adjusted using Helm chart values.

### Bug fixes

- Log exceptions encountered while parsing OpenID Connect responses from upstream providers, not just the deduced error message. Include the body of the response from the token endpoint if it could not be parsed as JSON.

### Other changes

- Include curl in the Gafaelfawr container for manual debugging of web request problems.

<a id='changelog-9.4.0'></a>
## 9.4.0 (2023-10-03)

### New features

- Gafaelfawr now supports the common LDAP configuration of recording group membership by full user DN rather than only username. Set `group_search_by_dn` to search for the user by full DN in the group tree. This requires LDAP also be used for user metadata.
- Allow the Gafaelfawr log level to be specified using any case (`info` as well as `INFO`, for example).

### Other changes

- Gafaelfawr now uses Pydantic v2. This should not result in any user-visible changes, but it is possible there will be some unexpected differences in data serialization or deserialization.
- Log the full contents of the upstream OIDC token before token verification if debug logging is enabled.

<a id='changelog-9.3.1'></a>
## 9.3.1 (2023-09-07)

### Bug fixes

- Gafaelfawr previously accepted a `group_mapping` rule whose value was a string rather than a list of group names and interpreted it as a list of single-letter group names corresponding to the letters in the string. This configuration now produces a validation error during startup.
- The Gafaelfawr Kubernetes operator now rejects `GafaelfawrIngress` resources with invalid scopes and sets an error status, rather than creating an `Ingress` resource that will always fail.

<a id='changelog-9.3.0'></a>
## 9.3.0 (2023-07-26)

### New features

- To configure Gafaelfawr to use the cluster-internal PostgreSQL service, use the Helm chart setting `config.internalDatabase` rather than setting an explicit URL. Setting `config.databaseUrl` to the internal PostgreSQL URL will still work for existing deployments, but using `config.internalDatabase` instead will be required in the future for correct secrets management.
- Gafaelfawr can now listen on additional hostnames specified by setting `ingress.additionalHosts` in the Helm configuration. Only token authentication will be supported for ingresses using those hostnames; interactive browser authentication will not work.

### Bug fixes

- Restore the newline after the output from `gafaelfawr generate-session-secret` and `gafaelfawr generate-token`, accidentally dropped in 9.2.1.

<a id='changelog-9.2.2'></a>
## 9.2.2 (2023-06-01)

### Bug fixes

- Limit the number of connections opened by the Redis connection pool, and wait for a connection to become available if all of them are in use.
- Use the asyncio version of Redis request retrying instead of (in conflict with everything else Gafaelfawr does) the sync version.

### Other changes

- Suppress logged warnings about invalid groups if they match the pattern of COmanage internal groups (start with `CO:`).

<a id='changelog-9.2.1'></a>
## 9.2.1 (2023-05-15)

### Bug fixes

- TCP keepalive for Redis connections apparently caused problems with holding connections open that the Redis server wanted to close. The TCP keepalive setting has been removed, which appears to increase the stability of the Redis connections.
- Connections to Redis are now retried longer (about eight seconds instead of three seconds) in the hope of surviving a Redis restart without failures.

### Other changes

- Gafaelfawr now uses the [Ruff](https://docs.astral.sh/ruff/) linter instead of flake8, isort, and pydocstyle.

<a id='changelog-9.2.0'></a>
## 9.2.0 (2023-04-19)

### New features

- Kerberos GSSAPI binds to authenticate to an LDAP server are now supported.
- To align with other services, the Gafaelfawr log level should now be set with `config.logLevel` rather than `config.loglevel` (note the capital `L`). The old setting is temporarily supported for backward compatibility but will be removed in a later release.
- Failures to deserialize or decrypt data stored in Redis are now reported to Slack if Slack alerting is enabled.
- Redis connection errors are now retried up to five times with exponential backoff before aborting with an error (for a total delay of up to about three seconds). TCP keepalive is now set on the Redis connection.

### Other changes

- The Gafaelfawr change log is now maintained using [scriv](https://scriv.readthedocs.io/en/latest/).
- Gafaelfawr no longer adds timestamps to each of its log messages. This was a workaround for Argo CD not displaying log timestamps, which has now been fixed.
- The documentation for running commands with `tox` has been updated for the new command-line syntax in tox v4. To run a local development server, use `tox run -e run`.
- Model API documentation is now generated with `autodoc_pydantic` to include proper field documentation.

## 9.1.0 (2023-03-17)

### New features

- Gafaelfawr now supports setting API and notebook quotas in its configuration, and calculates the quota for a given user based on their group membership. This quota information is returned by the `/auth/api/v1/user-info` route, but is not otherwise used by Gafaelfawr (yet).
- Server-side failures during login, such as inability to reach the authentication provider or invalid responses from the authentication provider, are now reported to Slack if a Slack webhook is configured.
- When using an OpenID Connect authentication provider, Gafaelfawr now supports looking up the GIDs of user groups in a ForgeRock Identity Management server (specifically, in the ``groups`` collection of the ``freeipa`` component).

### Bug fixes

- Explicitly disable caching of enrollment redirects. Some browsers appear to cache 307 redirects and redirected the user back to enrollment the next time they logged in.
- Uniformly use `Cache-Control: no-cache, no-store` to disable caching of errors and redirects. Previously, Gafaelfawr also added `must-revalidate` (but not `max-age`). This appears to not be necessary or useful with modern browsers.
- Correctly expand backtraces of uncaught exceptions in Uvicorn logs.
- Diagnose and display a proper error if the OpenID Connect token from the authentication provider contains multiple usernames.
- Return a status code of 500 instead of 403 for server-side errors during login.
- Errors in querying an external source of user information, such as Firestore or LDAP, are now caught in the `/auth` route and only logged, not reported to Slack as uncaught exceptions. The `/auth` route may receive multiple requests per second and should not report every error due to a possible external outage to Slack.
- Errors in querying an external source of user information in the `/auth/api/v1/user-info` route are now caught, reported to Slack, and result in an orderly error message instead of an uncaught exception.
- Set a timeout on Kubernetes watches in the Kubernetes operator to work around a Kubernetes server bug where watches of unlimited duration will sometimes go silent and stop receiving events.
- Mark Kubernetes object parsing failures as Kopf permanent failures so that the same version of the object will not be retried. Mark Kubernetes API failures as temporary failures so that the retry schedule is configurable.

### Other changes

- Gafaelfawr now supports camel-case in its configuration file to allow using the same names for most configuration settings and Helm chart values.
- More log messages related to retrieving user metadata, particularly those during initial login, now include the username of the user.

## 9.0.0 (2023-01-09)

### Backwards-incompatible changes

- Gafaelfawr now takes over 403 error responses from any protected service using a Gafaelfawr-generated ingress. 403 responses generated by the service itself will be passed to the client, but the body of the response and any `WWW-Authenticate` headers will be lost.
- User errors from the `/auth` route (not syntax errors like missing parameters) now uniformly return 403, since the NGINX `auth_request` module can only handle 401 and 403 responses. The actual status code is put in the `X-Error-Status` response header, and the JSON body (if relevant) in `X-Error-Body`.
- All ingresses created by Gafaelfawr use an `@autherror` error page for 403 responses that is added to each NGINX server scope by Phalanx. This custom location uses the `X-Error-Status` and `X-Error-Body` headers to tell NGINX to generate the correct error response.
- Remove the `/auth/forbidden` route, since a `Cache-Control` header is now automatically added via ingress-nginx to all errors. The `config.rewrite403` parameter to `GafaelfawrIngress` is still supported but does nothing, since its behavior is now the default.

### New features

- Gafaelfawr now accepts tokens in either the username or password portion of HTTP Basic Auth without requiring the other field be `x-oath-basic`. If both components are tokens, they must match; if they do not, Gafaelfawr raises an error.

## 8.0.0 (2022-12-16)

### Backwards-incompatible changes

- All commands that took a `--settings` option to specify the path to the configuration file now take a `--config-path` option instead. This name is clearer and avoids introducing a separate "settings" term.
- The default path to the Gafaelfawr configuration file is now taken from the `GAFAELFAWR_CONFIG_PATH` environment variable rather than `GAFAELFAWR_SETTINGS_PATH`, for the same reason.
- A `GafaelfawrIngress` that sets `config.loginRedirect` to true and also sets `config.authType` to `basic` is now rejected with an error, since this combination isn't possible. Previously, the `authType` setting was silently ignored.

### New features

- The response from the `/auth` now reflects `Authorization` and `Cookie` headers from the incoming request with Gafaelfawr tokens and secrets filtered out. `GafaelfawrIngress` resources use this to filter those secrets out of the request passed to the protected service, avoiding leaking user credentials to services. Manual ingress configurations should add `Authorization` and `Cookie` to the `nginx.ingress.kubernetes.io/auth-response-headers` annotation to get the benefits of this filtering.
- Add support for anonymous ingresses. If `config.scopes.anonymous` in a `GafaelfawrIngress` is set to true, no authentication or authorization will be done but Gafaelfawr will still be invoked as an auth subrequest handler solely to strip Gafaelfawr tokens and cookies from the `Authorization` and `Cookie` headers before passing the request to the protected service. This can also be configured manually using the new `/auth/anonymous` route.
- Add a `config.delegate.useAuthorization` field in `GafaelfawrIngress` and a `use_authorization` query parameter for the `/auth` route that, if set, also puts any delegated token in the `Authorization` header, as a bearer token, in the request sent to the protected service. This allows easier integration with some software that expects tokens in standard headers rather than Gafaelfawr's custom `X-Auth-Request-Token` header.
- `Ingress` resources generated from `GafaelfawrIngress` resources will be checked for correctness when Gafaelfawr starts, even if the `GafaelfawrIngress` resource has not been modified. This ensures changes to the generated `Ingress` due to Gafaelfawr code changes are applied to existing resources.

### Bug fixes

- If a user's login was rejected because they were not a member of any known groups, invalidate the LDAP cache for that user before returning the error. The user is likely to immediately try to fix this problem, and making them wait until the LDAP cache times out to see if the fix worked is confusing.

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

Gafaelfawr can now analyze the `X-Forwarded-For` header to determine the true client IP for logging purposes. This requires some configuration of both Gafaelfawr and the NGINX ingress. See [the logging documentation](https://gafaelfawr.lsst.io/dev/requirements.html#client-ips) for more information.

### New features

- Add new `proxies` setting to configure what network blocks should be treated as internal to the Kubernetes cluster.
- Set the client IP to the right-most IP in `X-Forwarded-For` that is not in a network block listed in `proxies`.
- Document the necessary NGINX ingress configuration for `X-Forwarded-For` analysis to work correctly.

### Other changes

- Fall back on logging `X-Original-URL` if `X-Original-URI` is not set.
- Stop recommending setting the `auth-request-redirect` annotation and do recommend setting the `auth-method` annotation.

## 1.2.0 (2020-05-07)

New in this release is an `/auth/forbidden` route that can be used to provide a non-cached 403 error page.

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
