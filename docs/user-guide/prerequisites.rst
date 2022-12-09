#############
Prerequisites
#############

Gafaelfawr only supports deployment as part of Phalanx_.
Deploying it outside of that environment is not supported or fully documented.

A PostgreSQL database is required.
Google Cloud SQL (including the Google Cloud SQL Auth Proxy) is supported (and preferred).

Redis is also used for storage.
The `Gafaelfawr Phalanx application <https://phalanx.lsst.io/applications/gafaelfawr/index.html>`__ will configure and deploy a private Redis server for this purpose.
You will need to configure persistent storage for that Redis server for any non-test deployment, which means that the Kubernetes cluster must provide persistent storage.

Gafaelfawr's routes must be exposed under the same hostname any service that it is protecting.
Currently, the only supported way to do this is to run Gafaelfawr and all of the services protected by that Gafaelfawr instance under the same host name.

If you need to protect services running under multiple host names, you will need to configure Gafaelfawr's ingress to add its routes (specifically ``/auth`` and ``/login``) to each of those host names.
There is no supported way to do this in Gafaelfawr's Helm configurstion.
You will need to add additional ``Ingress`` Kubernetes resources based off of those in the `Gafaelfawr Helm chart <https://github.com/lsst-sqre/phalanx/tree/master/services/gafaelfawr>`__.
