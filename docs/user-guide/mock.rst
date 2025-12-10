:og:description: Testing programs that use the Gafaelfawr client.

.. py:currentmodule:: rubin.gafaelfawr

######################################
Testing users of the Gafaelfawr client
######################################

The `MockGafaelfawr` class can be used to write unit tests of users of the Gafaelfawr Python client without needing a running Phalanx environment.
It simulates the subset of the Gafaelfawr API used by the Gafaelfawr client.

Creating the mock in a test fixture
===================================

`MockGafaelfawr` requires RESPX_ in addition to :py:mod:`rubin.gafaelfawr`.
Add ``respx`` to your project's development dependencies.

Then, add a fixture (usually to :file:`tests/conftest.py`) that calls `register_mock_gafaelfawr` and returns the `MockGafaelfawr` object.

.. code-block:: yaml

   import pytest_asyncio
   import respx
   from rubin.gafaelfawr import MockGafaelfawr, register_mock_gafaelfawr


   @pytest_asyncio.fixture
   async def mock_gafaelfawr(respx_mock: respx.Router) -> MockGafaelfawr:
       return await register_mock_gafaelfawr(respx_mock)

Overriding service discovery
----------------------------

`register_mock_gafaelfawr` uses service discovery to determine what Gafaelfawr URLs to mock.
You therefore must set up the service discovery mock before setting up the Gafaelfawr mock (such as by declaring it auto-use).
See the `Repertoire documentation <https://repertoire.lsst.io/user-guide/testing.html>`__ for more details on how to do so.

A simple Repertoire mock configuration that will work for most Gafaelfawr client testing is:

.. code-block:: python

   from pathlib import Path

   import pytest
   import respx
   from rubin.repertoire import Discovery, register_mock_discovery


   @pytest.fixture
   def mock_discovery(
       respx_mock: respx.Router,
       monkeypatch: pytest.MonkeyPatch,
   ) -> Discovery:
       monkeypatch.setenv("REPERTOIRE_BASE_URL", "https://example.com/repertoire")
       path = Path(__file__).parent / "data" / "discovery.json"
       return register_mock_discovery(respx_mock, path)

You will need to provide :file:`tests/data/discovery.json`.
The Gafaelfawr client asks for the URL of version ``v1`` of the the internal service ``gafaelfawr``.
The following mock service discovery information will therefore generally be sufficient for it.

.. code-block:: json

   {
     "services": {
       "internal": {
         "gafaelfawr": {
           "url": "https://data.example.com/auth/api",
           "versions": {
             "v1": {
               "url": "https://data.example.com/auth/api/v1"
             }
           }
         }
       }
     }
   }

You may need to add more entries if your application uses service discovery for other purposes.

Writing tests
=============

Any test you write that uses the Nublado client should depend on the ``mock_jupyter`` fixture defined above, directly or indirectly, so that the mock will be in place.
Alternately, you can mark the fixture as `auto-use <https://docs.pytest.org/en/stable/how-to/fixtures.html#autouse-fixtures-fixtures-you-don-t-have-to-request>`__.

Creating tokens
---------------

To create a Gafaelfawr token that will be recognized by the mock, call `MockGafaelfawr.create_token`.
If you will be using that token to get user information for other users, request the ``admin:userinfo`` scope by passing ``scopes=["admin:userinfo"]`` argument.

Registering user information
----------------------------

By default, even with a valid token, the mock will return a 404 response to requests for user information, which will trigger a `GafaelfawrNotFoundError` exception.
To set the user information returned for a given user, call `MockGafaelfawr.set_user_info` with the username and the `GafaelfawrUserInfo` data to return for that user.
The same data will be returned for requests via a token for that user and requests for user information for that user using a service token.

To clear the registered information again, call `MockGafaelfawr.set_user_info` with `None` for the user information argument.

Testing Gafaelfawr errors
-------------------------

Any Gafaelfawr reqeust supported by the mock can be configured to fail for a given user by calling `MockGafaelfawr.fail_on` and passing in the user and the operation or list of operations that should fail.
The operation should be chosen from `MockGafaelfawrAction`.
