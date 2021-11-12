# The dependencies need --allow-unsafe because sphinx depends on setuptools,
# which is normally not allowed to appear in a hashed dependency file.
.PHONY: update-deps
update-deps:
	pip install --upgrade pip-tools pip setuptools
	pip-compile --upgrade --build-isolation --allow-unsafe --generate-hashes --output-file requirements/main.txt requirements/main.in
	pip-compile --upgrade --build-isolation --allow-unsafe --generate-hashes --output-file requirements/dev.txt requirements/dev.in

# npm dependencies have to be installed for pre-commit eslint to work.
.PHONY: init
init:
	pip install --editable .
	pip install --upgrade -r requirements/main.txt -r requirements/dev.txt
	rm -rf .tox
	pip install --upgrade tox tox-docker
	pre-commit install
	cd ui && npm install

.PHONY: update
update: update-deps init

.PHONY: ui
ui:
	cd ui && npm run lint:fix
	cd ui && npm run build

# Filter out all "reference target not found" errors.  There are some
# legitimate warnings, but there are tons of spurious warnings because
# Sphinx appears not to understand imported symbols in type signatures and
# because some third-party modules don't have object inventories, making
# this warning effectively useless.
.PHONY: docs
docs:
	tox -e docs | egrep -v ' py:(class|exc|obj) reference target not found'
