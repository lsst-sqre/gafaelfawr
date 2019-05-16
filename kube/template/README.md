# Deploying

## Client Information

You first need a CILogon OAuth2 Client ID and secret.

Go here:
https://cilogon.org/oauth2/register

1. Add Client Name, e.g. "LSST LSP instance SSO"
2. Contact Email
3. Add hostname for Home URL
  - http://lsst-lsp-instance.example.com`)
4. Add callback URL for oauth2_proxy
  - `http://lsst-lsp-instance.example.com/oauth2/callback`
5. This is a private client

6. Select Scopes:

* email
* profile
* org.cilogon.userinfo

7. Refresh Token Lifetime - 24 hours
  - This is not really necessary, we can probably get by without refresh token

Save that information.
This is your client id and client secret.

### After submission

A separate email is required to CILogonhelp address to apply the client configuration
from the client `cilogon:/client_id/6ca7b54ac075b65bccb9c885f9ba4a75` to your new
client.

## Add TLS certificates
TLS certificates need to be added under the secret `tls` as a TLS secret.

## Run ./init.sh
This will gather required input and write out YAML files to a directory for 
your workspace. Those yaml files must be applied.

# Protecting services

Services behind the proxy are configured at the ingress level.

The typical annotation for a browser webapp in kubernetes is configured as follows:

```
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/auth-request-redirect: $request_uri
    nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-Token
    nginx.ingress.kubernetes.io/auth-sign-in: https://{{ HOSTNAME }}/oauth2/sign_in
    nginx.ingress.kubernetes.io/auth-url: https://{{ HOSTNAME }}/auth?capability={{ CAPABILITY }}
    nginx.ingress.kubernetes.io/configuration-snippet: |
      error_page 403 = "https://{{ HOSTNAME }}/oauth2/start?rd=$request_uri";
```

This will redirect to the login page for invalid sessions within a browser.
The token in `X-Auth-Request-Token` header will be signed by the issuer for
this domain.

Tokens will be signed by the token reissuer. The audience in the reissued tokens
is the domain name for most requests.

## Headers from proxy

The following headers are available from the proxy, any of these can be
added to the `nginx.ingress.kubernetes.io/auth-response-headers` annotation
for the ingress rule.

* `X-Auth-Request-Email`: If enabled and email is available, 
this will be set based on the `email` claim in the token.
* `X-Auth-Request-User`: If enabled and the field is available,
this will be set from token based on the `JWT_USERNAME_KEY` field,
which is typically the `uid` claim.
* `X-Auth-Request-Uid`: If enabled and the field is available,
this will be set from token based on the `JWT_UID_KEY` field,
which is typically the `uidNumber` claim
* `X-Auth-Request-Groups`: When a token has groups available
in the `isMemberOf` claim, the names of the groups will be
returned, comma-separated, in this header.
* `X-Auth-Request-Token`: If enabled, the encoded token will
be set. If `reissue_token` is true, the token is reissued first
* `X-Auth-Request-Token-Ticket`: When a ticket is available
for the token, we will return it under this header.
* `X-Auth-Request-Token-Capabilities`: If the token has
capabilities in the `scope` claim, they will be returned in this
header. If the token has
* `X-Auth-Request-Token-Capabilities-Accepted`: A space-separated 
list of token capabilities the reliant resource accepts
* `X-Auth-Request-Token-Capabilities-Satisfy`: The strategy
the reliant resource uses to accept a capability. `any` or `all`
WWW-Authenticate: If the request is unauthenticated, this
header will be set.

