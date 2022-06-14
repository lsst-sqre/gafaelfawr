##########
Gafaelfawr
##########

Gafaelfawr is the authentication and authorization front-end for the Vera C. Rubin Observatory Science Platform.
It's primary purpose is to serve as an NGINX ``auth_request`` backend.
It also provides a web page where people can create and manage long-lived tokens for use outside of a web browser, and can serve as a simple OpenID Connect server.
As a component of the Science Platform, it is designed for deployment with Kubernetes using the `Phalanx infrastructure <https://github.com/lsst-sqre/phalanx>`__.
Gafaelfawr requires the Kubernetes `NGINX ingress controller <https://github.com/kubernetes/ingress-nginx>`__.

Gafaelfawr is developed on `GitHub <https://github.com/lsst-sqre/gafaelfawr>`__.

Once Gafaelfawr is installed, API documentation is available at ``/auth/docs`` and ``/auth/redoc``.
The latter provides somewhat more detailed information.

Gafaelfawr is named for Glewlwyd Gafaelfawr, the knight who challenges King Arthur in *Pa gur yv y porthaur?* and, in later stories, is a member of his court and acts as gatekeeper.
Gafaelfawr is pronounced (very roughly) gah-VILE-vahwr.
(If you speak Welsh and can provide a better pronunciation guide, please open an issue!)

Installation
============

.. toctree::
   :maxdepth: 2

   configuration
   applications
   logging
   cli
   glossary

Changes
=======

.. toctree::
   :maxdepth: 1

   changelog

Architecture
============

.. toctree::
   :maxdepth: 2

   arch/overview
   arch/configuration
   arch/flow
   arch/routes
   arch/providers
   arch/scopes
   arch/storage
   arch/security
   arch/references

Development guide
=================

.. toctree::
   :maxdepth: 2

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
