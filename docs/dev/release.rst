#################
Release procedure
#################

This page gives an overview of how Gafaelfawr releases are made.
This information is only useful for maintainers.

Gafaelfawr's releases are largely automated through GitHub Actions (see the `ci.yaml`_ workflow file for details).
When a new release is created, Gafaelfawr Docker images are published on `GitHub <https://github.com/orgs/lsst-sqre/packages?repo_name=gafaelfawr>`__ tagged with that version.

.. _`ci.yaml`: https://github.com/lsst-sqre/gafaelfawr/blob/main/.github/workflows/ci.yaml

.. _regular-release:

Regular releases
================

Regular releases happen from the ``main`` branch after changes have been merged.
From the ``main`` branch you can release a new major version (``X.0.0``), a new minor version of the current major version (``X.Y.0``), or a new patch of the current major-minor version (``X.Y.Z``).
See :ref:`backport-release` to patch an earlier major-minor version.

Release tags are semantic version identifiers following the :pep:`440` specification.

1. Update the change log and dependencies
-----------------------------------------

Change log messages for each release are accumulated using scriv_.
See :ref:`dev-change-log` for more details.

When it comes time to make the release, there should be a collection of change log fragments in :file:`changelog.d`.
Those fragments will make up the change log for the new release.

Review those fragments to determine the version number of the next release.
Gafaelfawr follows semver_, so follow its rules to pick the next version:

- If there are any backward-incompatible changes, incremeent the major version number and set the other numbers to 0.
- If there are any new features, increment the minor version number and set the patch version to 0.
- Otherwise, increment the patch version number.

Then, run :command:`uv run scriv collect --version <version>` specifying the version number you decided on.
This will delete the fragment files and collect them into :file:`CHANGELOG.md` under an entry for the new release.
Review that entry and edit it as needed (proofread, change the order to put more important things first, remove blank lines between entries, etc.).

scriv will put blank lines between entries from different files.
You may wish to remove those blank lines to ensure consistent formatting by various Markdown parsers.

Update dependencies by running :command:`make update-deps`.

Create a PR from the collected change log and the updated dependencies.
Use a ``tickets/`` or ``t/`` branch to create this PR so that it will build a Docker container.

2. Test the new version and merge the PR
----------------------------------------

Test the Docker container built from the PR branch with the collected change log and updated dependencies in a development cluster on Phalanx.
For more details on how to do this, see :ref:`dev-server`.

When you have confirmed that the new version works correctly, merge the PR.

3. Create a GitHub release and tag
----------------------------------

Create a release using `GitHub's Release feature <https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository>`__:

#. For the tag, enter the version number of the release in the :guilabel:`Find or create a new tag` box in the dropdown under :guilabel:`Select tag`.
   The tag must follow the :pep:`440` specification since Gafaelfawr uses setuptools_scm_ to set version metadata based on Git tags.
   In particular, don't prefix the tag with ``v``.

   .. _setuptools_scm: https://github.com/pypa/setuptools-scm

#. Ensure the branch target is set appropriately (normally ``main``).

#. For the release title, repeat the version string.

#. Click the :guilabel:`Generate release notes` button to include the GitHub-generated summary of pull requests in the release notes.

#. In the release notes box above the generated notes, paste the contents of the :file:`CHANGELOG.md` entry for this release, without the initial heading specifying the version number and date.
   Adjust the heading depth of the subsections to use ``##`` instead of ``###`` to match the pull request summary.

The `ci.yaml`_ GitHub Actions workflow will upload documentation to https://gafaelfawr.lsst.io and a Docker image to the GitHub Container Registry.

4. Update Phalanx
-----------------

In the Phalanx_ repository under :file:`applications/gafaelfawr`, update the :file:`values.yaml` and :file:`values-{environment}.yaml` files for any changes in Nublado's configuration.

Then, as part of the same PR, update the version in :file:`applications/gafaelfawr/Chart.yaml` to the latest release tag.

.. _backport-release:

Backport releases
=================

The regular release procedure works from the main line of development on the ``main`` Git branch.
To create a release that patches an earlier major or minor version, you need to release from a **release branch.**

Creating a release branch
-------------------------

Release branches are named after the major and minor components of the version string: ``X.Y``.
If the release branch doesn't already exist, check out the latest patch for that major-minor version:

.. code-block:: sh

   git checkout X.Y.Z
   git switch -c X.Y
   git push -u

Developing on a release branch
------------------------------

Once a release branch exists, it becomes the "main" branch for patches of that major-minor version.
Pull requests should be based on, and merged into, the release branch.

If the development on the release branch is a backport of commits on the ``main`` branch, use :command:`git cherry-pick` to copy those commits into a new pull request against the release branch.

Releasing from a release branch
-------------------------------

Releases from a release branch are equivalent to :ref:`regular releases <regular-release>`, except that the release branch takes the role of the ``main`` branch.
