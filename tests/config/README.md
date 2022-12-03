# Test configurations

This directory contains configuration files for various test environments.
The contents of each file should be a Python format string.

The following variables will be replaced with paths to those secrets using format when the configuration file is generated:

- `bootstrap_token_file`
- `session_secret_file`
- `issuer_key_file`
- `github_secret_file`
- `oidc_secret_file`
- `oidc_server_secrets_file`
- `slack_webhook_file`

In addition, the following variables will be replaced with appropriate settings:

- `database_url`
