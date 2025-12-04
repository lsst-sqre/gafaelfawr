#################
Development guide
#################

This page provides procedures and guidelines for developing and contributing to Gafaelfawr.

Scope of contributions
======================

Gafaelfawr is an open source package, meaning that you can contribute to Gafaelfawr itself, or fork Gafaelfawr for your own purposes.

Since Gafaelfawr is intended for internal use by Rubin Observatory, community contributions can only be accepted if they align with Rubin Observatory's aims.
For that reason, it's a good idea to propose changes with a new `GitHub issue`_ before investing time in making a pull request.

Gafaelfawr is developed by the Rubin Observatory SQuaRE team.

.. _GitHub issue: https://github.com/lsst-sqre/gafaelfawr/issues/new

.. _dev-environment:

Setting up a local development environment
==========================================

Prerequisites
-------------

Gafaelfawr is developed using uv_.
You will therefore need it installed to set up a development environment.
See the `uv installation instructions <https://docs.astral.sh/uv/getting-started/installation/>`__ for details.

Gafaelfawr development requires Docker be installed locally.
The user doing development must be able to start and manage Docker containers.

Set up development environment
------------------------------

To develop Gafaelfawr, clone the repository and set up a virtual environment:

.. code-block:: sh

   git clone https://github.com/lsst-sqre/gafaelfawr.git
   cd gafaelfawr
   make init

This init step does three things:

1. Creates a Python virtual environment in the :file:`.venv` subdirectory with the packages needed to do Repertoire development installed.
2. Installs Gafaelfawr in an editable mode in that virtual environment.
3. Installs the pre-commit hooks.

You can activate the Gafaelfawr virtual environment if you wish with:

.. prompt:: bash

   source .venv/bin/activate

This is optional; you do not have to activate the virtual environment to do development.
However, if you do, you can omit :command:`uv run` from the start of all commands described below.
Also, editors with Python integration, such as VSCode, may work more smoothly if you activate the virtualenv before starting them.

.. _pre-commit-hooks:

Pre-commit hooks
================

The pre-commit hooks, which are automatically installed by running the :command:`make init` command on :ref:`set up <dev-environment>`, ensure that files are valid and properly formatted.
Some pre-commit hooks may automatically reformat code or update files:

blacken-docs
    Automatically formats Python code in reStructuredText documentation and docstrings.

ruff
    Lint Python code and attempt to automatically fix some problems.

When these hooks fail, your Git commit will be aborted.
To proceed, stage the new modifications and proceed with your Git commit.

If the ``uv-lock`` pre-commit hook fails, that indicates that the :file:`uv.lock` file is out of sync with the declared dependencies.
To fix this, run :command:`make update-deps` as described in :ref:`dev-updating-dependencies`.

.. _dev-run-tests:

Running tests
=============

Gafaelfawr uses nox_ as its automation tool for testing.

To run all tests:

.. prompt:: bash

   uv run nox

This will run several nox sessions to lint and type-check the code, run the test suite, and build the documentation.

To run a specific nox session, run:

.. prompt:: bash

   uv run nox -s <session>

For example, :command:`uv run nox -s typing` will only run mypy and not the rest of the tests.

Normally, the tests run without coverage analysis, since gathering that data slows down testing by about a third.
To test with coverage analysis, run:

.. prompt:: bash

   uv run nox -s test-coverage coverage-report

To list the available sessions, run:

.. prompt:: bash

   uv run nox --list

To run a specific test or list of tests, you can add test file names (and any other pytest_ options) after ``--`` when executing the ``test`` nox session.
For example:

.. prompt:: bash

   uv run nox -s test -- tests/cli_test.py

You can run a specific test function by appending two colons and the function name to the end of the file name.

Testing the Kubernetes operator
-------------------------------

To test the Kubernetes operator, you must have a Kubernetes cluster available that is not already running Gafaelfawr.

.. warning::

   The default Kubernetes credentials in your local Kubernetes configuration will be used to run the tests, whatever cluster that points to.
   In theory, you can use a regular Kubernetes cluster and only test namespaces starting with ``test-`` will be affected.

   In practice, this is not tested, and it is possible the tests will damage or destroy other applications or data running on the same Kubernetes cluster.

   If you want to run these tests manually rather than via CI, using Minikube for tests and carefully verifying that the default Kubernetes credentials are for the Minikube environment is strongly encouraged.

These tests are normally only run via Minikube_ configured via GitHub Actions.
If you want to run them locally, the following setup instructions may work, but are not tested and may have broken.

.. _Minikube: https://minikube.sigs.k8s.io/docs/

Install Minikube
^^^^^^^^^^^^^^^^

#. `Install Minikube <https://minikube.sigs.k8s.io/docs/start/>`__ for your platform.

#. Start a cluster using the Docker driver with the minimum recommended resources:

   .. prompt:: bash

      minikube start --driver=docker --cpus=4 --memory=8g --disk-size=100g

   The ``--kubernetes-version`` option can be used to specify the Kubernetes version to use.

#. Enable ingress support:

   .. prompt:: bash

      minikube addons enable ingress

Run the tests
^^^^^^^^^^^^^

To run all of the tests including Kubernetes tests, first check that your default Kubernetes environment is the one in which you want to run tests:

.. prompt:: bash

   kubectl config current-context

Then, run:

.. prompt:: bash

   uv run nox -s test-full

Add the ``coverage-report`` session to also get a test coverage report.

Building documentation
======================

Documentation is built with Sphinx_.
It is built as part of a normal test run to check that the documentation can still build without warnings, or can be built explicitly with:

.. _Sphinx: https://www.sphinx-doc.org/en/master/

.. prompt:: bash

   uv run nox -s docs

The build documentation is located in the :file:`docs/_build/html` directory.

Additional dependencies required only for the documentation build should be added to the ``docs`` dependency group in :file:`pyproject.toml`.

Documentation builds are incremental, and generate and use cached descriptions of the internal Python APIs.
If you see errors in building the Python API documentation or have problems with changes to the documentation (particularly diagrams) not showing up, try a clean documentation build with:

.. prompt:: bash

   uv run nox -s docs-clean

This will be slower, but it will ensure that the documentation build doesn't rely on any cached data.

To check the documentation for broken links, run:

.. prompt:: bash

   uv run nox -s docs-linkcheck

.. _dev-server:

Running a development server
============================

Properly and fully testing Gafaelfawr requires deploying it in a Kubernetes cluster and testing its interactions with Kubernetes and the NGINX ingress.
Gafaelfawr therefore doesn't support starting a local development server; that would only allow limited testing of the API, and in practice we never used that ability when we supported it.

Therefore, to run a development version of Gafaelfawr for more thorough manual testing, deploy it in a development Phalanx environment.
See `the Phalanx documentation <https://phalanx.lsst.io/developers/deploy-from-a-branch.html>`__ for more details on how to do this.

You will generally want to override the Gafaelfawr image and pull policy in your Phalanx development branch to point at the Docker image for your development version.
Do this by adding the following to the appropriate :file:`values-{environment}.yaml` file:

.. code-block:: yaml

   image:
     tag: tickets-DM-XXXXX
     pullPolicy: Always

Replace the tag with the name of your development branch.
Slashes in the branch name should be changed to dashes in the tag name.

.. note::

   Be sure you use a branch naming pattern that will cause the Gafaelfawr GitHub Actions configuration to build and upload a Docker image.
   By default, this means the branch name must begin with ``tickets/`` or ``t/``.
   You can change this in :file:`.github/workflows/ci.yaml` under the ``build`` step.

Updating dependencies
=====================

To update dependencies, run:

.. prompt:: bash

   make update-deps

This will update all pinned Python dependencies, update the versions of the pre-commit hooks, and, if needed, update the version of uv pinned in the GitHub Actions configuration and :file:`Dockerfile`.

To also update the development virtualenv, instead run:

.. prompt:: bash

   make update-deps

You may wish to do this at the start of a development cycle so that you're using the latest versions of the linters.
You may also want to update dependencies immediately before release so that each release includes the latest dependencies.

Dependency structure
--------------------

All Gafaelfawr dependencies are configured in :file:`pyproject.toml` like a regular Python package.
Runtime dependencies are configured in ``project.dependencies``, and development dependencies are configured under ``dependency-groups``.
The following dependency groups are used:

dev
    Dependencies required to run the test suite, not including the dependencies required to run tox itself.

docs
    Dependencies required to build the documentation.

lint
    Dependencies required to run pre-commit_ and to lint the code base.

nox
    Dependencies required to run nox_.

typing
    Dependencies required to run mypy_

These dependency groups are used by the nox build script in :file:`noxfile.py` to install the appropriate dependencies based on the nox session.
The development virtualenv in :file:`.venv` will have all of these dependency groups installed so the developer can freely use commands such as :command:`ruff` and :command:`mypy`.

A frozen version of all of these dependencies is managed by uv_ in the file :file:`uv.lock`.
This is used to pin all dependencies so that they only change when a developer intends to update them and is prepared to run tests to ensure nothing broke.
This is the file updated with :command:`make update` or :command:`make update-deps`.

Temporary Git dependencies
--------------------------

By default, all Python dependencies are retrieved from PyPI.

Sometimes during development it may be useful to test Gafaelfawr against an unreleased version of one of its dependencies.
uv_ supports this by setting a `dependency source <https://docs.astral.sh/uv/concepts/projects/dependencies/#dependency-sources>`__.

For example, to use the current main branch of Safir_ instead of the latest released version, add the following to the end of :file:`pyproject.toml`:

.. code-block:: toml

   [tool.uv.sources]
   safir = { git = "https://github.com/lsst-sqre/safir", branch = "main", subdirectory = "safir" }

The :command:`uv add` command can be used to configure these sources if desired.
As always, after changing dependencies, run :command:`make update` or :command:`make update-deps`.
Gafaelfawr will now use the unreleased version of Safir.

Do not release new non-alpha versions of Gafaelfawr with these types of Git dependencies.
The other package should be released first before a new version of Gafaelfawr is released.

.. _db-migrations:

Creating database migrations
============================

Gafaelfawr uses Alembic_ to manage and perform database migrations.
Alembic is invoked automatically when the Gafaelfawr server is started.
Whenever the database schema changes, you will need to create an Alembic migration.

To do so, take the following steps:

#. Make any planned code changes that will change the database schema.

#. Ask Alembic to autogenerate a database migration to the new schema:

   .. prompt:: bash

      uv run nox -s create-migration <message>

   Replace ``<message>`` with a short, human-readable summary of the change, ending in a period.
   This command will create a new file in :file:`alembic/versions` starting with the current date.

#. Edit the created file in :file:`alembic/versions` and adjust it as necessary.
   See the `Alembic documentation <https://alembic.sqlalchemy.org/en/latest/autogenerate.html>`__ for details about what Alembic can and cannot autodetect.

   One common change that Alembic cannot autodetect is changes to the valid values of enum types.
   You will need to add Alembic code to the ``upgrade`` function of the migration such as:

   .. code-block:: python

      op.execute("ALTER TYPE tokentype ADD VALUE 'oidc' IF NOT EXISTS")

   Another common change that it cannot autodetect is changes from ``VARCHAR`` to ``TEXT`` columns in PostgreSQL.

   If you need to manually compare the old and new schemas to look for changes like that, you can dump the database schema created by your current working tree with:

   .. prompt:: bash

      nox -s dump-schema

All schema changes are backwards-incompatible changes for versioning and change log purposes.
Remember to add a note to :file:`CHANGELOG.md` that the new version will require a schema migration.

.. _dev-change-log:

Updating the change log
=======================

Gafaelfawr uses scriv_ to maintain its change log.

When preparing a pull request, run :command:`uv run scriv create`.
This will create a change log fragment in :file:`changelog.d`.
Edit that fragment, removing the sections that do not apply and adding entries fo this pull request.
You can pass the ``--edit`` flag to :command:`uv run scriv create` to open the created fragment automatically in an editor.

Change log entries use the following sections:

- **Backward-incompatible changes**
- **New features**
- **Bug fixes**
- **Other changes** (for minor, patch-level changes that are not bug fixes, such as logging formatting changes or updates to the documentation)

The change log entries should be written in imperative tense and describe to the user the change in behavior or the impact on the user at a high level.
Technical descriptions of how the change was implemented belong in commit messages, not change log entries.

Rules for what to put in the change log
---------------------------------------

Changes that are not visible to the user, including minor documentation changes, should not have a change log fragment.
"User" here means a user of the Gafaelfawr API, the administrator of a Phalanx environment where Gafaelfawr is deployed, or the maintainer of an application that uses a Gafaelfawr Kubernetes resource.

Changes that require changes to the Phalanx Helm chart but do not require changes to any of the per-environment :file:`values-{environment}.yaml` files are not user-visible in this sense.
They do not warrant change log entries unless they have some other user-visible impact.
Even if they are user-visible, changes that do not require modifications to :file:`values-{environment}.yaml` are generally not backwards-incompatible changes.
Normally, they are features or bug fixes.

If the change to a dependency results in a user-visible behavior change, describe that change in the Gafaelfawr change log.
Do not only say that the dependency was updated.
If the change to a dependency has no user-visible impact, do not create a change log entry for it.

Every release is implicitly assumed to update all pinned dependencies.
This should not be noted in the change log unless there is a user-visible behavior change.

Formatting change log entries
-----------------------------

These entries will eventually be cut and pasted into the release description for the next release, so the Markdown for the change descriptions must be compatible with GitHub's Markdown conventions for the release description.
Specifically:

- Each bullet point should be entirely on one line, even if it contains multiple sentences.
  This is an exception to the normal documentation convention of a newline after each sentence.
  Unfortunately, GitHub interprets those newlines as hard line breaks, so they would result in an ugly release description.
- Be cautious with complex markup, such as nested bullet lists, since the formatting in the GitHub release description may not be what you expect and manually repairing it is tedious.

.. _style-guide:

Style guide
===========

Code
----

- Gafaelfawr follows the :sqr:`072` Python style guide and uses the repository layout documented in :sqr:`075`.

- The code formatting follows :pep:`8`, though in practice lean on Ruff to format the code for you.

- Use :pep:`484` type annotations.
  The :command:`uv run nox -s typing` command, which runs mypy_, ensures that the project's types are consistent.

- Gafaelfawr uses the Ruff_ linter with most checks enabled.
  Its primary configuration is in :file:`ruff-shared.toml`, which should be an exact copy of the version from the `FastAPI Safir app template <https://github.com/lsst/templates/blob/main/project_templates/fastapi_safir_app/example/ruff-shared.toml>`__.
  Try to avoid ``noqa`` markers except for issues that need to be fixed in the future.
  Tests that generate false positives should normally be disabled, but if the lint error can be avoided with minor rewriting that doesn't make the code harder to read, prefer the rewriting.

- Write tests for pytest_.

Documentation
-------------

- Follow the `LSST DM User Documentation Style Guide`_, which is primarily based on the `Google Developer Style Guide`_.

- Document the Python API with numpydoc-formatted docstrings.
  See the `LSST DM Docstring Style Guide`_.

- Follow the `LSST DM ReStructuredTextStyle Guide`_.
  In particular, ensure that prose is written **one-sentence-per-line** for better Git diffs.

.. _`LSST DM User Documentation Style Guide`: https://developer.lsst.io/user-docs/index.html
.. _`Google Developer Style Guide`: https://developers.google.com/style/
.. _`LSST DM Docstring Style Guide`: https://developer.lsst.io/python/style.html
.. _`LSST DM ReStructuredTextStyle Guide`: https://developer.lsst.io/restructuredtext/style.html
