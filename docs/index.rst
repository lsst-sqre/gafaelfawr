##########
Gafaelfawr
##########

Gafaelfawr is the authentication and authorization front-end for the Vera C. Rubin Observatory Science Platform.

It's primary purpose is to serve as an NGINX ``auth_request`` backend.
It also provides a web page where people can create and manage long-lived tokens for use outside of a web browser, and can serve as a simple OpenID Connect server.
As a component of the Science Platform, it is designed for deployment with Kubernetes using the `Phalanx infrastructure <https://github.com/lsst-sqre/phalanx>`__.
Gafaelfawr requires the Kubernetes `NGINX ingress controller <https://github.com/kubernetes/ingress-nginx>`__.

Gafaelfawr is developed on `GitHub <https://github.com/lsst-sqre/gafaelfawr>`__.
It is deployed via Phalanx_.

Gafaelfawr is part of the Rubin Science Platform identity management system.
Its design is documented in :dmtn:`234`, and its implementation in :dmtn:`224`.
History and decisions made during its development are documented in :sqr:`069`.
Read those documents for a more complete picture of how Gafaelfawr fits into a larger identity management system.

Gafaelfawr is named for Glewlwyd Gafaelfawr, the knight who challenges King Arthur in *Pa gur yv y porthaur?* and, in later stories, is a member of his court and acts as gatekeeper.
Gafaelfawr is pronounced (very roughly) gah-VILE-vahwr.
(If you speak Welsh and can provide a better pronunciation guide, please open an issue!)

Usage
=====

.. toctree::
   :maxdepth: 2

   user-guide/index
   api

.. toctree::
   :hidden:

   changelog

Development
===========

.. toctree::
   :maxdepth: 2

   dev/index
