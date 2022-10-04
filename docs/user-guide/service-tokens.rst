##############
Service tokens
##############

If a service needs a token to make authenticated calls on its own behalf, the recommended way to create such service tokens is with Gafaelfawr's Kubernetes secret support.
Create a ``GafaelfawrServiceToken`` object in the same namespace as the service:

.. code-block:: yaml

   apiVersion: gafaelfawr.lsst.io/v1alpha1
   kind: GafaelfawrServiceToken
   metadata:
     name: <name>
     namespace: <namespace>
   spec:
     service: <service-name>
     scopes:
       - <scope-1>
       - <scope-2>

Gafaelfawr will then create and manage a secret with the same name and in the same namespace.
That secret will have one ``data`` element, ``token``, which will contain a valid Gafaelfawr service token.
The service name and the scopes of that token will be determined by the settings in ``spec``.
Any labels or annotations on the ``GafaelfawrServiceToken`` object will be copied to the created secret.

You can then provide that secret to the service via whatever mechanism is the most convenient, such as by setting an environment variable with its value using the normal Kubernetes ``Pod`` specification.

``<service-name>`` must begin with ``bot-`` and otherwise be a valid Gafaelfawr username.
