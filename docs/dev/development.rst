#################
Development guide
#################

This page provides procedures and guidelines for developing and contributing to Gafaelfawr.

Scope of contributions
======================

Gafaelfawr is an open source package, meaning that you can contribute to Gafaelfawr itself, or fork Gafaelfawr for your own purposes.

Since Gafaelfawr is intended for internal use by Rubin Observatory, community contributions can only be accepted if they align with Rubin Observatory's aims.
For that reason, it's a good idea to propose changes with a new `GitHub issue`_ before investing time in making a pull request.

Gafaelfawr is developed by the LSST SQuaRE team.

.. _GitHub issue: https://github.com/lsst-sqre/gafaelfawr/issues/new

.. _dev-environment:

Setting up a local development environment
==========================================

Prerequisites
-------------

Gafaelfawr uses uv_ for all dependency management.
A reasonably recent version of :command:`uv` must already be installed.
See `the uv installation instructions <https://docs.astral.sh/uv/getting-started/installation/>`__ if needed.

Gafaelfawr development requires Docker be installed locally.
The user doing development must be able to start and manage Docker containers.

Set up development environment
------------------------------

To develop Gafaelfawr, create a virtual environment with :command:`uv venv` and then run :command:`make init`.

.. prompt:: bash

   git clone https://github.com/lsst-sqre/gafaelfawr.git
   cd gafaelfawr
   uv venv
   make init

This init step does three things:

1. Installs Gafaelfawr in a virtualenv in the :file:`.venv` directory, including the dependency groups for local development.
2. Installs pre-commit_, tox_, and the necessary tox plugins.
3. Installs the pre-commit hooks.

On macOS hosts, you may need to run the following before running :command:`make init` and in the same terminal window.

.. prompt:: bash

   export LDFLAGS="-L/usr/local/opt/openssl/lib"

Otherwise, OpenSSL isn't on the default linker path and some Python extensions may not build.
This must be set in any terminal window where you may run :command:`tox`.

Finally, you can optionally enter the Gafaelfawr development virtualenv with:

.. prompt:: bash

   source .venv/bin/activate

This is optional; you do not have to activate the virtualenv to do development.
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

uv-lock
    Update the :file:`uv.lock` file if dependencies in :file:`pyproject.toml` have changed.

When these hooks fail, your Git commit will be aborted.
To proceed, stage the new modifications and proceed with your Git commit.

.. _dev-run-tests:

Running tests
=============

To test all components of Gafaelfawr other than the Kubernetes operator (see below), run tox_, which tests the library the same way that the CI workflow does:

.. prompt:: bash

   uv run tox run

This uses tox-docker to start PostgreSQL and Redis Docker containers for the tess to use, so Docker must be installed and the user running tox must have permission to create Docker containers.

To run the tests with coverage analysis and generate a report, run:

.. prompt:: bash

   uv run tox run -e py-coverage,coverage-report

To see a listing of test environments, run:

.. prompt:: bash

   uv run tox list

To run a specific test environment, run:

.. prompt:: bash

   uv run tox -e <environment>

For example, ``uv run tox -e typing`` will only run mypy and not the rest of th
e tests.

To run a specific test or list of tests, you can add test file names (and any other pytest_ options) after ``--`` when executing the ``py`` or ``py-full`` tox environment.
For example:

.. prompt:: bash

   uv run tox run -e py -- tests/handlers/api_tokens_test.py

You can run a specific test function by appending two colons and the function name to the end of the file name.

Testing the Kubernetes operator
-------------------------------

To test the Kubernetes operator, you must have a Kubernetes cluster available that is not already running Gafaelfawr.
This is only tested with Minikube_, which is the approach used by CI.

.. _Minikube: https://minikube.sigs.k8s.io/docs/

.. warning::

   The default Kubernetes credentials in your local Kubernetes configuration will be used to run the tests, whatever cluster that points to.
   In theory, you can use a regular Kubernetes cluster and only test namespaces starting with ``test-`` will be affected.

   In practice, this is not tested, and it is possible the tests will damage or destroy other applications or data running on the same Kubernetes cluster.

   If you want to run these tests manually rather than via CI, using Minikube for tests and carefully verifying that the default Kubernetes credentials are for the Minikube environment is strongly encouraged.

To set up Minikube:

#. `Install Minikube <https://minikube.sigs.k8s.io/docs/start/>`__ for your platform.

#. Start a cluster using the Docker driver with the minimum recommended resources:

   .. prompt:: bash

      minikube start --driver=docker --cpus=4 --memory=8g --disk-size=100g  --kubernetes-version=1.21.5

   The ``--kubernetes-version`` option can be used to specify the Kubernetes version to use.

#. Enable the NGINX Ingress Controller using the  `Minikube ingress addon <https://kubernetes.io/docs/tasks/access-application-cluster/ingress-minikube/>`__:

   .. prompt:: bash

      minikube addons enable ingress

To run all of the tests including Kubernetes tests, first check that your default Kubernetes environment is the one in which you want to run tests:

.. prompt:: bash

   kubectl config current-context

Then, run:

.. prompt:: bash

   uv run tox run -e py-full

Add the ``coverage-report`` environment to also get a test coverage report.

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
Slashes will be replaced with underscores.

.. note::

   Be sure you use a branch naming pattern that will cause the Gafaelfawr GitHub Actions configuration to build and upload a Docker image.
   By default, this means the branch name must begin with ``tickets/``.
   You can change this in :file:`.github/workflows/ci.yaml` under the ``build`` step.

Updating dependencies
=====================

All Gafaelfawr dependencies are configured in :file:`pyproject.toml` like a regular Python package.
Runtime dependencies are configured in ``project.dependencies``, and development dependencies are configured under ``dependency-groups``.
The following dependency groups are used:

dev
    Dependencies required to run the test suite, not including the dependencies required to run tox itself.

docs
    Dependencies required to build the documentation.

lint
    Dependencies required to run pre-commit_ and to lint the code base.

tox
    Dependencies required to run tox_.

typing
    Dependencies required to run mypy_

These dependency groups are used by the tox configuration in :file:`tox.ini` to install the appropriate dependencies based on the tox action.
The development virtualenv in :file:`.venv` will have all of these dependency groups installed so the developer can freely use commands such as :command:`ruff` and :command:`mypy`.

A frozen version of all of these dependencies is managed by uv_ in the file :file:`uv.lock`.
This is used to pin all dependencies so that they only change when a developer intends to update them and is prepared to run tests to ensure nothing broke.

After changing any dependency, run :command:`make update-deps` to rebuild the :file:`uv.lock` file and update any JavaScript dependencies.
To also update the development virtualenv, run :command:`make update` instead.

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
To do this, follow the `Safir schema migration documentation <https://safir.lsst.io/user-guide/database/schema.html#creating-database-migrations>`__.
Add :command:`uv run` to the start of all tox commands shown there, unless you have activated the Gafaelfawr development virtualenv.

Building documentation
======================

Documentation is built with Sphinx_:

.. _Sphinx: https://www.sphinx-doc.org/en/master/

.. prompt:: bash

   uv run tox run -e docs

The build documentation is located in the :file:`docs/_build/html` directory.

To check the documentation for broken links, run:

.. prompt:: bash

   uv run tox run -e docs-linkcheck

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

Versioning assumes that Gafaelfawr is installed via Phalanx, so changes to its internal configuration file do not count as backward-incompatible chnages unless they require changes to Helm :file:`values.yaml` files.

Do not include a change log entry solely for updating pinned dependencies, without any visible change to Gafaelfawr's behavior.
Every release is implicitly assumed to update all pinned dependencies.

These entries will eventually be cut and pasted into the release description for the next release, so the Markdown for the change descriptions must be compatible with GitHub's Markdown conventions for the release description.
Specifically:

- Each bullet point should be entirely on one line, even if it contains multiple sentences.
  This is an exception to the normal documentation convention of a newline after each sentence.
  Unfortunately, GitHub interprets those newlines as hard line breaks, so they would result in an ugly release description.
- Avoid using too much complex markup, such as nested bullet lists, since the formatting in the GitHub release description may not be what you expect and manually editing it is tedious.

.. _style-guide:

Style guide
===========

Code
----

- Gafaelfawr follows the :sqr:`072` Python style guide.

- The code formatting follows :pep:`8`, though in practice lean on Ruff to format the code for you.

- Use :pep:`484` type annotations.
  The :command:`uv run tox run -e typing` command, which runs mypy_, ensures that the project's types are consistent.

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
