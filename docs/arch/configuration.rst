######################
Configuration settings
######################

The only supported way to deploy Gafaelfawr is via its Helm chart.
User configuration is done through Helm values.

Internally, Gafaelfawr uses `pydantic`_ for configuration.
Most configuration settings are provided via a YAML file that is constructed from a ``ConfigMap`` Kubernetes resource created by the Helm chart.
Some secrets are referenced by paths in that YAML file and mounted as a secret volume in the Gafaelfawr pods.
Others are passed via environment variables.

.. _pydantic: https://pydantic-docs.helpmanual.io/

The exact mechanisms for how the Helm chart communicates configuration settings to Gafaelfawr are an internal implementation detail and are intentionally not documented in the manual.
Future work will likely move, rename, or restructure those configuration mechanisms.

Development settings
--------------------

The development server launched via ``tox -e run`` uses the configuration in ``examples/gafaelfawr-dev.yaml``.
See :ref:`dev-server` for instructions on how to modify that file to get a fully working development environment.

One environment variable may be of interest for running a development copy of Gafaelfawr:

``GAFAELFAWR_UI_PATH``
    The path to the compiled UI served under ``/auth/tokens``.
    Gafaelfawr will serve files under this path as static files under the ``/auth/tokens`` route.
    This should be the contents of the ``ui/public`` directory after running ``make ui``.

    Normally this is handled by either the ``tox -e run`` command, the ``tox -e docker`` command, or the release Docker image.
