#!/bin/bash
#
# Set up the database and then start the Gafaelfawr application.

set -eu

# Start the server under k5start if Kerberos is configured.
cmd="uvicorn --factory gafaelfawr.main:create_app --host 0.0.0.0 --port 8080"
if [ -f "/etc/krb5.conf" ] && [ -f "/etc/krb5.keytab" ]; then
    exec k5start -aqUFf /etc/krb5.keytab -- $cmd
else
    exec $cmd
fi
