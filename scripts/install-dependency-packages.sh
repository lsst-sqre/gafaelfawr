#!/bin/bash

# Install additional packages required only to build Gafaelfawr and construct
# its virtualenv, but not required at runtime.
#
# Since this script runs in the dependency image, which is not used as a basis
# for the runtime image, it doesn't have to clean up after itself to minimize
# the final image size, but it does anyway to reduce the size of the
# intermediate image stored in Docker Hub.

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

# Required to build binary Python modules and use nvm.
apt-get -y install --no-install-recommends build-essential curl

# Delete cached files we don't need any more.
apt-get clean
rm -rf /var/lib/apt/lists/*

# Clone the nvm repository and install it.
cd /opt
git clone https://github.com/nvm-sh/nvm.git nvm
cd nvm
git checkout v0.37.2

# Disable verbose shell logging from this point onward because nvm is very
# noisy otherwise.
set +x

# Configure nvm.  Since no version of Node is installed, this will exit with
# status 3, which we want to ignore.
. nvm.sh || true

# Install Node and Gatsby.  There is an .nvmrc file in /opt that controls what
# version of Node to install.
cd /opt
nvm install
nvm use
npm install -g gatsby-cli
