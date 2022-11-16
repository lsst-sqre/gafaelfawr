Kubermetes custom resource definitions
======================================

This directory contains custom resource definitions (CRDs) for Kubernetes.
The resulting resources are read by the Gafaelfawr Kubernetes operator and used as templates and configuration to create and manage other resources.

Nothing except Gafaelfawr's test suite uses these files directly.
The copy of these CRDs installed into a Kubernetes cluster are the ones included with the Gafaelfawr Helm chart in the [Phalanx](https://phalanx.lsst.io/) repository.
However, these are the canonical versions, and the copies in Phalanx should be kept in sync with these files.
