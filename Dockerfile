# This Dockerfile has four stages:
#
# base-image
#   Updates the base Python image with security patches and common system
#   packages. This image becomes the base of all other images.
# dependencies-image
#   Installs third-party dependencies (requirements/main.txt) into a virtual
#   environment. This virtual environment is ideal for copying across build
#   stages.
# install-image
#   Installs the app into the virtual environment.
# runtime-image
#   - Copies the virtual environment into place.
#   - Runs a non-root user.
#   - Sets up the entrypoint and port.

FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8 as base-image

# Update system packages
COPY scripts/install-base-packages.sh .
RUN ./install-base-packages.sh

# Install the latest pip and setuptools.
RUN pip install --upgrade --no-cache-dir pip setuptools wheel

# Install the app's Python runtime dependencies.
COPY requirements/main.txt ./requirements.txt
RUN pip install --quiet --no-cache-dir -r requirements.txt

FROM base-image AS runtime-image

# Install the app in /app, which is expected by the base image.
COPY src /app

# Copy over the prestart script that handles database setup.
COPY scripts/prestart.sh /app/prestart.sh

# We use a module name other than app, so tell the base image that.
ENV MODULE_NAME=gafaelfawr.main
