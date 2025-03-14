#####################
Cross-origin requests
#####################

A cross-origin HTTP request is one initiated by a web site at a different origin (meaning the tuple of scheme, hostname, and port) than the target of the request.
Cross-origin requests are restricted according to `complex rules <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS>`__ in the HTTP security model.

Gafaelfawr does not protect against cross-origin `simple requests <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests>`__ (requests that do not require CORS preflight).
This is up to the protected web application.
However, note that :ref:`disabling cookie authentication <allow-cookies>` is generally effective at forcing a CORS preflight check, since inclusion of an ``Authorization`` header requires preflight checking.

.. _cors-preflight:

CORS preflight policy
=====================

Gafaelfawr implements the following authorization policy for CORS preflight requests to authenticated ingresses:

- An ``OPTIONS`` request containing an ``Origin`` header matching the hostname of the base URL of the Science Platform is allowed through to the protected site to respond to as it wishes.
  This is true even if the protected site is served from a hostname that does not match the base URL.

- If :ref:`subdomain support is enabled <helm-subdomains>`, an ``OPTIONS`` request containing an ``Origin`` header for any hostname that is a subdomain of the base URL is also allowed through to the protected site to respond to as it wishes.

- All other ``OPTIONS`` requests are rejected.

The intended effect of this policy is to allow protected applications to control their CORS policy for requests from other components of the same instance of the Science Platform, but to reject all cross-origin requests from outside the Science Platform, regardless of the opinions of the protected application.

Anonymous ingresses pass all requests through to the underlying application, including ``OPTIONS`` requests.

Other ``OPTIONS`` requests
==========================

All ``OPTIONS`` requests to authenticated ingresses that do not contain an ``Origin`` header are rejected with a 404 error by default.

This means that sites protected by Gafaelfawr will normally not support the non-CORS use of ``OPTIONS`` to determine supported HTTP methods.
This use of ``OPTIONS`` is not widely supported or used.

Protected services that do use ``OPTIONS`` for operations other than CORS preflight checks, such as WebDAV servers, must explicitly enable them in the ``GafaelfawrIngress`` configuration.
See :ref:`ingress-allow-options`.
