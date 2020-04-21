##########
Gafaelfawr
##########

Gafaelfawr is the authentication and authorization front-end for the Vera C. Rubin Observatory Science Platform.
It's primary purpose is to serve as an nginx ``auth_request`` backend.
It also provides a web page where people can create and manage long-lived tokens for use outside of a web browser.
As a component of the Science Platform, it is designed for deployment with Kubernetes.
Gafaelfawr requires the Kubernetes `NGINX ingress controller <https://github.com/kubernetes/ingress-nginx>`__.

Gafaelfawr is developed on `GitHub <https://github.com/lsst/gafaelfawr>`__.

Installation
============

.. toctree::
   :maxdepth: 1

   kubernetes
   configuration
   glossary
   changelog

Architecture
============

.. toctree::
   :maxdepth: 1

   arch/issuer

Development guide
=================

.. toctree::
   :maxdepth: 1

   dev/development
   dev/release

API
===

.. toctree::
   :maxdepth: 2

   api

Indices
=======

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
