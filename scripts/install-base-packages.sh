#!/bin/bash

# This script updates packages in the base Docker image that's used by both the
# build and runtime images, and gives us a place to install additional
# system-level packages with apt-get.
#
# Based on the blog post:
# https://pythonspeed.com/articles/system-packages-docker/

# Bash "strict mode", to help catch problems and bugs in the shell
# script. Every bash script you write should include this. See
# http://redsymbol.net/articles/unofficial-bash-strict-mode/ for
# details.
set -euo pipefail

# Display each command as it's run.
set -x

# Tell apt-get we're never going to be able to give manual
# feedback:
export DEBIAN_FRONTEND=noninteractive

# Update the package listing, so we know what packages exist:
apt-get update

# Install security updates:
apt-get -y upgrade

# libpq-dev is required by psycopg2. Most of the other packages are required
# by bonsai for LDAP binds or to manage the Kerberos ticket cache. curl and
# krb5-user are not strictly needed, but are useful for debugging.
apt-get -y install --no-install-recommends curl krb5-user kstart        \
        libldap2-dev libldap-common libsasl2-dev libsasl2-modules       \
        libsasl2-modules-gssapi-mit libpq-dev

# Delete cached files we don't need anymore:
apt-get clean
rm -rf /var/lib/apt/lists/*
