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
