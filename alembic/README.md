# Gafaelfawr Alembic configuration

This directory contains the Alembic configuration for managing the Gafaelfawr database.
It is installed into the Gafaelfawr Docker image and is used to check whether the schema is up-to-date at startup of any Gafaelfawr component.
It is also used by the Helm hook that updates the Gafaelfawr schema if `config.updateSchema` is enabled.

## Generating new migrations

For detailed instructions on how to generate a new Alembic migration, see [the Gafaelfawr development documentation](https://gafaelfawr.lsst.io/dev/development.html#creating-database-migrations).

The `gafaelfawr.yaml` file in this directory is a minimal Gafaelfawr configuration that is sufficient to install the Gafaelfawr schema and run Alembic in a local PostgreSQL image running inside Docker.
This file is not used at runtime.
It is used by the nox sessions described in the above documentation.
