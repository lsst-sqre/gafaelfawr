:og:description: Learn how to use the Gafaelfawr client and REST APIs.

###############
Gafaelfawr APIs
###############

Applications written in Python that want to use the Gafaelfawr API should use the :doc:`Gafaelfawr client </user-guide/client>`.
Applications written in other languages, and administrators performing manual operations, can use the REST API directly.

Some portions of the REST API, although documented for completeness, are only intended for use by web browsers or by Kubernetes.
The API intended for other applications consists of the routes under ``/api``.

.. toctree::
   :caption: Python client

   client

.. toctree::
   :caption: Server

   rest
