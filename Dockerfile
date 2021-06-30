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
#   - Sets up additional supporting scripts.
#   - Configures gunicorn.

FROM tiangolo/uvicorn-gunicorn:python3.8-slim as base-image

# Update system packages
COPY scripts/install-base-packages.sh .
RUN ./install-base-packages.sh
RUN rm ./install-base-packages.sh

FROM base-image AS dependencies-image

# Determine the Node version that we want to install
COPY .nvmrc /opt/.nvmrc

# Install some additional packages required for building dependencies.
COPY scripts/install-dependency-packages.sh .
RUN ./install-dependency-packages.sh

# Create a Python virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv $VIRTUAL_ENV
# Make sure we use the virtualenv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
# Put the latest pip and setuptools in the virtualenv
RUN pip install --upgrade --no-cache-dir pip setuptools wheel

# Install the app's Python runtime dependencies
COPY requirements/main.txt ./requirements.txt
RUN pip install --quiet --no-cache-dir -r requirements.txt

FROM dependencies-image AS install-image

# Use the virtualenv
ENV PATH="/opt/venv/bin:$PATH"

# Install the Gafaelfawr Python application.
COPY . /workdir
WORKDIR /workdir
RUN pip install --no-cache-dir .

FROM base-image AS runtime-image

# Copy the virtualenv.
COPY --from=install-image /opt/venv /opt/venv

# Copy in the built UI and tell Gafaelfawr where it is.
COPY ui/public /app/ui/public
ENV GAFAELFAWR_UI_PATH=/app/ui/public

# Make sure we use the virtualenv
ENV PATH="/opt/venv/bin:$PATH"

# Copy over the prestart script that handles database setup.
COPY scripts/prestart.sh /app/prestart.sh

# We use a module name other than app, so tell the base image that.  This
# does not copy the app into /app as is recommended by the base Docker
# image documentation and instead relies on the module search path as
# modified by the virtualenv.
ENV MODULE_NAME=gafaelfawr.main

# The default starts 40 workers, which exhausts the available connections
# on a micro Cloud SQL PostgreSQL server and seems excessive since we can
# scale with Kubernetes.  Cap the workers at 10.
ENV MAX_WORKERS=10

# Run on port 8080 instead of the FastAPI default for backward compatibility.
ENV PORT=8080
