"""Kubernetes operator framework.

This module imports all of the handlers for Gafaelfawr's Kubernetes operator
and serves as an entry point for Kopf_.

Examples
--------
Start the Gafaelfawr Kubernetes operator with the following command:

.. code-block: shell

   kopf run -A -m gafaelfawr.kubernetes.operator
"""

from . import startup, tokens

__all__ = ["startup", "tokens"]
