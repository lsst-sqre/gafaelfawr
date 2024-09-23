#############
Prerequisites
#############

Gafaelfawr only supports deployment as part of Phalanx_.
Deploying it outside of that environment is not supported or documented.

A PostgreSQL database is required.
Google Cloud SQL (including the Google Cloud SQL Auth Proxy) is supported (and preferred).

Redis is used for storage.
The `Gafaelfawr Phalanx application <https://phalanx.lsst.io/applications/gafaelfawr/index.html>`__ will configure and deploy a private Redis server for this purpose.
You will need to configure persistent storage for that Redis server for any non-test deployment, which means that the Kubernetes cluster must provide persistent storage.

Gafaelfawr supports token-based authentication for any domain, but only supports interactive browser-based authentication and cookies for a single domain.
