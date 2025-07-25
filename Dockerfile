# This Dockerfile has three stages:
#
# base-image
#   Updates the base Python image with security patches and common system
#   packages. This image becomes the base of all other images.
# install-image
#   Installs third-party dependencies into a virtual environment and
#   installs the application into /app. This directory will be copied
#   across build stages.
# runtime-image
#   - Copies the virtual environment into place.
#   - Runs as a non-root user.
#   - Sets up the entrypoint and port.

FROM python:3.13.5-slim-bookworm AS base-image

# Update system packages
COPY scripts/install-base-packages.sh .
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    ./install-base-packages.sh && rm ./install-base-packages.sh

FROM base-image AS install-image

# Install uv.
COPY --from=ghcr.io/astral-sh/uv:0.8.0 /uv /bin/uv

# Determine the Node version that we want to install
COPY .nvmrc /opt/.nvmrc

# Install some additional packages required for building dependencies.
COPY scripts/install-dependency-packages.sh .
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    ./install-dependency-packages.sh

# Disable hard links during uv package installation since we're using a
# cache on a separate file system.
ENV UV_LINK_MODE=copy

# Install the dependencies.
WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-default-groups --compile-bytecode --no-install-project

# Install the Gafaelfawr Python application.
ADD . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --no-deps --compile-bytecode .

FROM base-image AS runtime-image

# Create a non-root user
RUN useradd --create-home appuser

# Copy the virtualenv.
COPY --from=install-image /app /app

# Set the working directory and tell Gafaelfawr where the UI is.
WORKDIR /app
ENV GAFAELFAWR_UI_PATH=/app/ui/public

# Switch to the non-root user.
USER appuser

# Expose the port.
EXPOSE 8080

# Make sure we use the uv virtualenv.
ENV PATH="/app/.venv/bin:$PATH"

# Run the application.
CMD ["/app/scripts/start.sh"]
