################
Response headers
################

The following headers may be added to the response from a service protected by Gafaelfawr.
They will only be added for services behind an authenticated ``GafaelfawrIngress`` resource, not an anonymous one.

.. _headers-rate-limit:

Rate limit headers
==================

``Retry-After``
    Only sent on 429 responses once the rate limit has been exceeded.
    Specifies the time at which the rate limit will reset and the user will be able to make requests again.
    The value is an HTTP date.

``X-RateLimit-Limit``
    This request is subject to a rate limit.
    The value of this header is the total number of requests permitted in each time window, which currently is always one minute.
    See ``X-RateLimit-Remaining`` for the number of requests left in that interval.

``X-RateLimit-Remaining``
    The number of requests to this service remaining in the user's quota.
    The quota will reset at the time given by ``X-RateLimit-Reset``.

``X-RateLimit-Reset``
    The time at which the rate limit quota will reset, in seconds since epoch.
    At this time, the number of requests seen will be reset to zero, and the user will receive another full allotment of their quota.

``X-RateLimit-Resource``
    The name of the resource being rate-limited.
    This will match the ``service`` setting of the ``GafaelfawrIngress`` Kubernetes resource.
    Clients can use this header to understand what requests are subject to a given quota.

``X-RateLimit-Used``
    The number of requests to this resource seen within the rate limit period.
    This will be ``X-RateLimit-Limit`` minus ``X-RateLimit-Remaining``.

The ``X-RateLimit`` headers are sent for successful responses, error responses from the underlying service, and 429 responses.
The ``Retry-After`` header is only sent as part of a 429 response.
