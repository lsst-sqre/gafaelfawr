##########################
Configuration architecture
##########################

The only supported way to deploy Gafaelfawr is via its Helm chart.
User configuration is done through Helm values.

Internally, Gafaelfawr uses Pydantic_ for configuration.
Most configuration settings are provided via a YAML file that is constructed from a ``ConfigMap`` Kubernetes resource created by the Helm chart.
Secrets are referenced by paths in that YAML file and mounted as a secret volume in the Gafaelfawr pods.
The Pydantic settings are then turned into frozen dataclasses internally, which are passed to Gafaelfawr components as configuration.

.. _Pydantic: https://docs.pydantic.dev/latest/

The exact mechanisms for how the Helm chart communicates configuration settings to Gafaelfawr are an internal implementation detail and are intentionally not documented in the manual.
Updates to Gafaelfawr move, rename, or restructure those configuration mechanisms without notice.
This is only considered a breaking change for versioning purposes if the Helm chart configuration changes.

Development settings
====================

The development server launched via ``tox run -e run`` uses the configuration in ``examples/gafaelfawr-dev.yaml``.
See :ref:`dev-server` for instructions on how to modify that file to get a fully working development environment.

One environment variable may be of interest for running a development copy of Gafaelfawr:

``GAFAELFAWR_UI_PATH``
    The path to the compiled UI served under ``/auth/tokens``.
    Gafaelfawr will serve files under this path as static files under the ``/auth/tokens`` route.
    This should be the contents of the ``ui/public`` directory after running ``make ui``.

    Normally this is handled by either the ``tox run -e run`` command, the ``tox run -e py`` command, or the release Docker image.

Pydantic and dataclasses
========================

It would be ideal if Pydantic could be used directly for settings without rewriting the Pydantic ``Settings`` class into dataclasses.
However, there is a missing feature in the Pydantic system that interfere with this.

There are two options for loading Kubernetes secrets in a pod.
One is to inject them via environment variables.
The other is to expose the secrets as files in a temporary file system created by Kubernetes.
Unfortunately, neither of these work with Pydantic given the constraints of Gafaelfawr.

The problem with the environment variable approach is that Pydantic does not really support setting individual keys of a nested configuration model via environment variables.
There are workarounds, but they're awkward and hard to use.
Gafaelfawr separates its configuration by subsystem so that only the relevant configuration can be passed into that subsystem, which in turn allows centralization of the checks for whether particularly configurations are `None` without littering the code with them.
This requires injecting secrets into nested configuration models.

Support for loading secrets from disk doesn't fair much better.
Pydantic does support a mechanism for loading configuration keys from disk files, but it doesn't support nested structure.

After a couple of tries at using Pydantic directly, the current approach, while somewhat repetitive, seems easier to support.
It also has the advantage that certain settings can be duplicated into the settings for multiple components during configuration post-processing.

Passing secrets
===============

As mentioned above, there are two common ways to pass secrets into a Kubernetes Pod: pass the secret as an environment variable, or mount it (or less commonly write it) as a file in the Pod and read it from disk.
Gafaelfawr uniformly uses the second approach.

Neither approach is generally recommended by security experts.
Instead, the most common recommendation is to not use the Kubernetes secret store at all (since it is not very secure), and instead have each service retrieve its secrets dynamically from a secret service, such as Vault_.

.. _Vault: https://www.vaultproject.io/

We've chosen to accept the higher risk of using the Kubernetes secret store, since it's much more convenient, avoids a hard external dependency on a running Vault server, and is more familiar with anyone who has administered Kubernetes.

Given that, each service has to make a choice between passing secrets as environment variables or passing them as files.
Both may be leaked if an attacker gains code execution in the Pod.
Gafaelfawr uses files instead of environment variables because they seem moderately more difficult to leak.
Some vulnerabilities leak the contents of the environment without allowing arbitrary code execution, and arbitrary file read provides access to the environment anyway (via ``/proc/self/environ``).

This choice is not very significant for security purposes, and is partly motivated by awkwardness in the Pydantic Settings classes in using environment variables to initialize attributes in sub-models.

Another approach would be to stop materializing all of the secrets in memory during startup and instead add a ``get_secret`` helper that reads the secret from disk when it's needed.
This would also provide a hook for a future security improvement to obtain secrets from some better source than Kubernetes secrets, such as Vault.
This is not yet implemented, but may be in the future.
