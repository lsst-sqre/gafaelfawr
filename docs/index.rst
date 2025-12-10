:og:description: Authentication and authorization for Phalanx.

.. toctree::
   :hidden:

   User guide <user-guide/index>
   API <api/index>
   Operations <operations/index>
   Change log <changelog>
   Contributing <dev/index>

##########
Gafaelfawr
##########

Gafaelfawr provides the authentication and authorization infrastructure for Phalanx_ environments, including the Vera C. Rubin Observatory Science Platform.

Its primary purpose is to serve as an NGINX ``auth_request`` backend.
It also provides a web page where people can create and manage long-lived tokens for use outside of a web browser, and can serve as a simple OpenID Connect server.
Gafaelfawr requires the Kubernetes `NGINX ingress controller <https://github.com/kubernetes/ingress-nginx>`__.

Gafaelfawr is developed on `GitHub <https://github.com/lsst-sqre/gafaelfawr>`__.

Gafaelfawr is part of the Rubin Science Platform identity management system.
Its design is documented in :dmtn:`234`, and its implementation in :dmtn:`224`.
History and decisions made during its development are documented in :sqr:`069`.
Read those documents for a more complete picture of how Gafaelfawr fits into a larger identity management system.

.. grid:: 2

   .. grid-item-card:: User Guide
      :link: user-guide/index
      :link-type: doc

      Learn how to protect services with Gafaelfawr and use the Gafaelfawr client.

   .. grid-item-card:: API
      :link: api/index
      :link-type: doc

      See the full API documentation for the Gafaelfawr client.

.. grid:: 2

   .. grid-item-card:: Operations
      :link: operations/index
      :link-type: doc

      Learn how to configure and administer the Gafaelfawr server.

   .. grid-item-card:: Development
      :link: dev/index
      :link-type: doc

      Learn how to contribute to the Gafaelfawr codebase.

Gafaelfawr is named for Glewlwyd Gafaelfawr, the knight who challenges King Arthur in *Pa gur yv y porthaur?* and, in later stories, is a member of his court and acts as gatekeeper.
Gafaelfawr is pronounced (very roughly) gah-VILE-vahwr.
(If you speak Welsh and can provide a better pronunciation guide, please open an issue!)
