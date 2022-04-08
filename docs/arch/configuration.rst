######################
Configuration settings
######################

The only supported way to deploy Gafaelfawr is via its Helm chart.
User configuration is done through Helm values.

Internally, Gafaelfawr uses `Pydantic`_ for configuration.
Most configuration settings are provided via a YAML file that is constructed from a ``ConfigMap`` Kubernetes resource created by the Helm chart.
Secrets are referenced by paths in that YAML file and mounted as a secret volume in the Gafaelfawr pods.
The Pydantic settings are then turned into frozen dataclasses internally, which are passed to Gafaelfawr components as configuration.

.. _Pydantic: https://pydantic-docs.helpmanual.io/

The exact mechanisms for how the Helm chart communicates configuration settings to Gafaelfawr are an internal implementation detail and are intentionally not documented in the manual.
Updates to Gafaelfawr move, rename, or restructure those configuration mechanisms without notice.
This is only considered a breaking change if the Helm chart configuration changes.

Development settings
====================

The development server launched via ``tox -e run`` uses the configuration in ``examples/gafaelfawr-dev.yaml``.
See :ref:`dev-server` for instructions on how to modify that file to get a fully working development environment.

One environment variable may be of interest for running a development copy of Gafaelfawr:

``GAFAELFAWR_UI_PATH``
    The path to the compiled UI served under ``/auth/tokens``.
    Gafaelfawr will serve files under this path as static files under the ``/auth/tokens`` route.
    This should be the contents of the ``ui/public`` directory after running ``make ui``.

    Normally this is handled by either the ``tox -e run`` command, the ``tox -e docker`` command, or the release Docker image.

Pydantic and dataclasses
========================

It would be ideal if Pydantic could be used directly for settings without rewriting the Pydantic ``Settings`` class into dataclasses.
However, there are two missing features in the Pydantic system that interfere with this:

#. Loading secrets from disk directly in the Pydantic model is difficult.
   Pydantic does support a mechanism for loading configuration keys from disk files, but it doesn't support nested structure, which we want so that the configurations for different internal Gafaelfawr components are kept separate (which in turn simplifies a lot of code that otherwise would have to check for `None` repeatedly).
#. Pydantic provides poor support for loading a YAML file whose file name is not known statically.
   We have to use ``parse_obj``, which in turn makes some other Pydantic Settings constructor arguments accessible only via static configuration.

After a couple of tries at using Pydantic directly, the current approach, while somewhat repetitive, seems easier to support.

Passing secrets
===============

There are two common ways to pass secrets into a Kubernetes Pod: pass the secret as an environment variable, or mount it (or less commonly write it) as a file in the Pod and read it from disk.
Gafaelfawr uniformly uses the second approach.

Neither approach is generally recommended by security experts.
Instead, the most common recommendation is to not use the Kubernetes secret store at all (since it is not very secure), and instead have each application retrieve its secrets dynamically from a secret service, such as Vault_.

.. _Vault: https://www.vaultproject.io/

We've chosen to accept the higher risk of using the Kubernetes secret store, since it's much more convenient, avoids a hard external dependency on a running Vault server, and is more familiar with anyone who has administered Kubernetes.

Given that, each application has to make a choice between passing secrets as environment variables or passing them as files.
Both may be leaked if an attacker gains code execution in the Pod.
Gafaelfawr uses files instead of environment variables because they seem moderately more difficult to leak.
Some vulnerabilities leak the contents of the environment without allowing arbitrary code execution, and arbitrary file read provides access to the environment anyway (via ``/proc/self/environ``).

This choice is not very significant for security purposes, and is partly motivated by awkwardness in the Pydantic Settings classes in using environment variables to initialize attributes in sub-models.
