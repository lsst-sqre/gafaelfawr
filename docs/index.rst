##########
Gafaelfawr
##########

Gafaelfawr is the authentication and authorization front-end for the Vera C. Rubin Observatory Science Platform.
It's primary purpose is to serve as an NGINX ``auth_request`` backend.
It also provides a web page where people can create and manage long-lived tokens for use outside of a web browser, and can serve as a simple OpenID Connect server.
As a component of the Science Platform, it is designed for deployment with Kubernetes using the `Phalanx infrastructure <https://github.com/lsst-sqre/phalanx>`__.
Gafaelfawr requires the Kubernetes `NGINX ingress controller <https://github.com/kubernetes/ingress-nginx>`__.

Gafaelfawr is developed on `GitHub <https://github.com/lsst-sqre/gafaelfawr>`__.

Gafaelfawr is part of the Rubin Science Platform identity management system.
Its design is documented in DMTN-234_, and its implementation in DMTN-224_.
History and decisions made during its development are documented in SQR-069_.
Read those documents for a more complete picture of how Gafaelfawr fits into a larger identity management system.

.. _DMTN-224: https://dmtn-224.lsst.io/
.. _DMTN-234: https://dmtn-234.lsst.io/
.. _SQR-069: https://sqr-069.lsst.io/

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

API
===

.. toctree::
   :maxdepth: 2

* `REST API <api.html>`__

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
   arch/providers
   arch/scopes
   arch/storage
   arch/security
   arch/internals
   arch/references

Development guide
=================

.. toctree::
   :maxdepth: 2

   dev/development
   dev/release

Indices
=======

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
