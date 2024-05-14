# Gafaelfawr Alembic configuration

This directory contains the Alembic configuration for managing the Gafaelfawr database.
It is installed into the Gafaelfawr Docker image and is used to check whether the schema is up-to-date at startup of any Gafaelfawr component.
It is also used by the Helm hook that updates the Gafaelfawr schema if `config.updateSchema` is enabled.

## Generating new migrations

For detailed instructions on how to generate a new Alembic migration, see [the Gafaelfawr development documentation](https://gafaelfawr.lsst.io/dev/development.html#creating-database-migrations).

Two of the files in this directory are here only to support creating migrations.
The `gafaelfawr.yaml` file in this directory is a minimal Gafaelfawr configuration that is sufficient to install the Gafaelfawr schema and run Alembic in a local PostgreSQL image running inside Docker.
`docker-compose.yaml` is the corresponding [docker-compose](https://docs.docker.com/compose/) configuration file that starts that PostgreSQL instance (and the necessary Redis instance).
These files are not used at runtime.
They are used by the tox environments described in the above documentation.
