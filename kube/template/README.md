# Deploying

## Prerequisites
This process assumes your ingress for the hostname has already been set up.
We do not rely on tls secrets for any deployments under that assumptions

### Getting Client Information

If you do not have a client as secret, you first need to obtain one from CILogon OAuth2 Client ID and secret.

Go here:
https://cilogon.org/oauth2/register

1. Add Client Name, e.g. "LSST LSP instance SSO"
2. Contact Email
3. Add hostname for Home URL
  - `http://lsst-lsp-instance.example.com`
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

## Configuring Auth Services

### Prerequisites

- pip, or
- git, to clone this repo
- curl, in case you don't have pip or git

#### Source
Clone this repo, switch to this directory (kube/template).

```
git clone https://github.com/lsst/jwt_authorizer
cd jwt_authorizer/kube/template
```

If you don't have git, you can also get it with curl:
```
curl -sSLO https://github.com/lsst/jwt_authorizer/archive/master.tar.gz
tar xvzf master.tar.gz
cd jwt-authorizer-master/kube/template
```

#### Running the init scripts
init.sh relies on j2cli. By default it will try to use a local version
then fall back to a version in in docker. If you would like to override that.
You can override with the J2_BIN for with your own executable. 

You can `pip install j2cli[yaml]` otherwise and it should work too, but it may try to
install an old version of pyyaml.

If you don't have pip on the system, but at least have python installed, you should be
able to bootstrap everything, as long as you at least have curl:

```
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py --user
pip install --user j2cli[yaml]
```

You will want to modify your PATH too:
`PATH=$PATH:$HOME/.local/bin:$HOME/bin`

### Run ./init.sh
This will gather required input and write out YAML files to a directory for 
your workspace. Those yaml files must be applied.

### Applying the Config and Cleanup
You can `kubectl apply -R -f .` the config.

The output of this step will, by necessity, contain secrets in the output
directory. You have some secrets in the clear, you may want to save those 
somewhere safe (or delete them, if appropriate). The public signing key that
jwt_authorizer uses to sign tokens is available in a PEM format under
`public.pem`. *Applications that validate the JWT tokens,
such as the notebook may need this file*. Other application may rely on the
JWKS-formatted public key that's deployed to 
`https://{{ HOSTNAME }}/.well-known/jwks.json`.


## Configuring Applications

### Protecting services

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

### Headers from proxy

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
header.
* `X-Auth-Request-Token-Capabilities-Accepted`: A space-separated 
list of token capabilities the reliant resource accepts
* `X-Auth-Request-Token-Capabilities-Satisfy`: The strategy
the reliant resource uses to accept a capability. `any` or `all`
* `WWW-Authenticate`: If the request is unauthenticated, this
header will be set according to the configuration.

### Verifying tokens
This deploys a JWKS file to .well-known/jwks.json. Some applications
may use that file for verifying a token they receive is valid.

A public key is also available, if it was saved. (See [previous section](#applying-the-config-and-leanup))
If it's not saved, it is also derivable from the jwks.json file.
