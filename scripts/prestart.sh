#!/bin/bash
#
# The prestart script for the Docker image.  Currently creates the database.
# Eventually, this will call Alembic to handle database migrations.

set -eux

PYTHONPATH=/app; export PYTHONPATH
python /app/gafaelfawr/cli.py init
