#!/bin/bash

# Install additional packages required only to build Gafaelfawr and construct
# its virtualenv, but not required at runtime.
#
# Since this script runs in the dependency image, which is not used as a basis
# for the runtime image, it doesn't have to clean up after itself to minimize
# the final image size.

# Bash "strict mode", to help catch problems and bugs in the shell
# script. Every bash script you write should include this. See
# http://redsymbol.net/articles/unofficial-bash-strict-mode/ for details.
set -euo pipefail

# Display each command as it's run.
set -x

# Tell apt-get we're never going to be able to give manual feedback.
export DEBIAN_FRONTEND=noninteractive

# Install various dependencies that may be required to install mobu.
#
# build-essential: sometimes needed to build Python modules
# git: required by setuptools_scm
# libffi-dev: sometimes needed to build cffi, a cryptography dependency
apt-get -y install --no-install-recommends build-essential git libffi-dev
