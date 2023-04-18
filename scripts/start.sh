#!/bin/bash
#
# Start the Gafaelfawr application inside the Docker image.  Currently creates
# the database.  Eventually, this will call Alembic to handle database
# migrations.

set -eu

# Always initialize the database if needed. This shouldn't require LDAP access
# and thus isn't run with Kerberos tickets.
gafaelfawr init

# Start the server under k5start if Kerberos is configured.
cmd="uvicorn --factory gafaelfawr.main:create_app --host 0.0.0.0 --port 8080"
if [ -f "/etc/krb5.conf" ] && [ -f "/etc/krb5.keytab" ]; then
    exec k5start -aqUFf /etc/krb5.keytab -- $cmd
else
    exec $cmd
fi
