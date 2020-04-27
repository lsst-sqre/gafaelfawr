This directory contains settings files for various test environments.
The contents of each file should be a Python format string.
The variables `session_secret_file`, `issuer_key_file`, `github_secret_file`, and `oidc_secret_file` will be replaced with paths to those secrets using format when the test application is drected.
