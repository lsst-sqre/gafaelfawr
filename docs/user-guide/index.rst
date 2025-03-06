##########
User guide
##########

Gafaelfawr was written to run within the Vera C. Rubin Science Platform.
While there is nothing intrinsic in Gafaelfawr that would prevent it from working in some other environment, only installation via `Phalanx <https://github.com/lsst-sqre/phalanx>`__ is supported or has been tested.

Also see the `Phalanx Gafaelfawr application documentation <https://phalanx.lsst.io/applications/gafaelfawr/index.html>`__ for more operational documentation and procedures.

.. toctree::
   :caption: Configuration

   prerequisites
   provider
   secrets
   helm
   administrators

.. toctree::
   :caption: Protecting services

   ingress-overview
   gafaelfawringress
   cors
   quotas
   service-tokens
   openid-connect

.. toctree::
   :caption: Reference

   headers
   logging
   cli
   metrics
