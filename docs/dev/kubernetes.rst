####################
Kubernetes resources
####################

Gafaelfawr uses Kopf_ as the framework for its Kubernetes operators.
Currently, the only version of both ``GafaelfawrIngress`` and ``GafaelfawrServiceToken`` is ``v1alpha1``.
The CRDs are in the :file:`crds` directory at the root of the Gafaelfawr repository and in the :file:`applications/gafaelfawr/crds` directory in Phalanx.
The latter are the versions of the CRDs installed by the chart, and should be a copy of the versions from the latest released version of Gafaelfawr.

Future CRD changes
==================

Unfortunately, Kopf currently `doesn't support conversion webhooks <https://github.com/nolar/kopf/issues/956>`__, so there is no simple way to make backward-incompatible changes to the CRDs.
For now, all changes to the CRDs have to be backward compatible, which means not removing any field and making all new fields optional.

The following desirable changes to the existing object schemas are blocked on finding a way to properly follow the `CRD update process <https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/>`__.

Changes to ``GafaelfawrIngress``
--------------------------------

- Make ``config.service`` mandatory and remove ``config.delegate.internal.service``.
- Delete the ``config.rewrite403`` field.

There will likely also be changes needed to support multiple domains and cross-domain authentication, but those have not yet been specified.

Changes to ``GafaelfawrServiceToken``
-------------------------------------

- Support a list of tokens to create, each of which become fields in the generated ``Secret``.
- Support generating the necessary tokens for `mobu <https://mobu.lsst.io/>`__ and `noteburst <https://noteburst.lsst.io/>`__, which may require multiple users with metadata generated from a template and an algorithm.
  The goal would be to remove their need to have ``admin:token`` permissions and instead pre-generate all of their tokens.
