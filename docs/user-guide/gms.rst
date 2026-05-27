:og:description: Learn how to use the Gafaelfawr IVOA GMS API.

.. _gms:

################
IVOA GMS queries
################

Gafaelfawr also provides an implementation of the `IVAO Group Membership Service protocol (version 1.0) <https://www.ivoa.net/documents/GMS/20220222/REC-GMS-1.0.html>`__.
This is a simple text-based API that allows a service with a delegated credential (see :ref:`delegated-tokens`) to get the group membership of an authenticated user.

To use this API, send a GET request to ``/auth/gms``.
Include the delegated token in an ``Authorization`` header as a bearer token.
The response will be a list of the names of the groups of which the user is a member.
Each group name will end in a newline.
If the user is not a member of any groups, the body of the response will be empty.

One or more ``group`` query parameters may be provided to the ``/auth/gms`` GET request.
If present, only the intersection between the user's group membership and the groups specified in ``group`` query parameters will be returned.
This allows for a simple check to see if the user is a member of one or more specific groups: List those groups in ``group`` query parameters, and then if the response has a 200 HTTP status code and a non-empty body, the user is a member of at least one of those groups.

As specified in the GMS protocol, the HTTP ``Expires`` header should be used to determine how long the result of a GMS query can be safely cached by the client.

.. note::

   GMS support is primarily for applications that prefer to use IVOA protocols or that were written to work in a generic IVOA environment.
   Most Gafaelfawr-native applications should use the :ref:`python-client` instead, or the richer :doc:`Gafaelfawr REST API </api/rest>`.
