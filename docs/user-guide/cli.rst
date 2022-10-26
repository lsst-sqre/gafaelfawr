Command-line interface
======================

.. click:: gafaelfawr.cli:main
   :prog: gafaelfawr
   :nested: full

Kubernetes operator
-------------------

The Kubernetes operator is not started through the ``gafaelfawr`` command-line entry point because Kopf_ wants to have full control over how it's run.
Instead, to start the operator, use:

.. code-block:: shell

   kopf run -A --log-format=json -m gafaelfawr.operator
