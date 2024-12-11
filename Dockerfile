# This Dockerfile has three stages:
#
# base-image
#   Updates the base Python image with security patches and common system
#   packages. This image becomes the base of all other images.
# install-image
#   Installs third-party dependencies (requirements/main.txt) into a virtual
#   environment. This virtual environment is ideal for copying across build
#   stages.
# runtime-image
#   - Copies the virtual environment into place.
#   - Runs as a non-root user.
#   - Sets up the entrypoint and port.

FROM python:3.12.8-slim-bookworm AS base-image

# Update system packages
COPY scripts/install-base-packages.sh .
RUN ./install-base-packages.sh && rm ./install-base-packages.sh

FROM base-image AS install-image

# Install uv.
COPY --from=ghcr.io/astral-sh/uv:0.5.8 /uv /bin/uv

# Determine the Node version that we want to install
COPY .nvmrc /opt/.nvmrc

# Install some additional packages required for building dependencies.
COPY scripts/install-dependency-packages.sh .
RUN ./install-dependency-packages.sh

# Create a Python virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN uv venv /opt/venv

# Make sure we use the virtualenv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install the app's Python runtime dependencies
COPY requirements/main.txt ./requirements.txt
RUN uv pip install --compile-bytecode --verify-hashes --no-cache \
    -r requirements.txt

# Install the Gafaelfawr Python application.
COPY . /workdir
WORKDIR /workdir
RUN uv pip install --compile-bytecode --no-cache .

FROM base-image AS runtime-image

# Create a non-root user
RUN useradd --create-home appuser

# Copy the virtualenv.
COPY --from=install-image /opt/venv /opt/venv

# Copy the Alembic configuration and migrations, and set that path as the
# working directory so that Alembic can be run with a simple entry command
# and no extra configuration.
COPY --from=install-image /workdir/alembic.ini /app/alembic.ini
COPY --from=install-image /workdir/alembic /app/alembic
WORKDIR /app

# Copy in the built UI and tell Gafaelfawr where it is.
COPY ui/public /app/ui/public
ENV GAFAELFAWR_UI_PATH=/app/ui/public

# Copy the startup script
COPY scripts/start.sh /start.sh

# Make sure we use the virtualenv
ENV PATH="/opt/venv/bin:$PATH"

# Switch to the non-root user.
USER appuser

# Expose the port.
EXPOSE 8080

# Run the application.
CMD ["/start.sh"]
