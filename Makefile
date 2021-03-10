# The dependencies need --allow-unsafe because sphinx and gunicorn depend on
# setuptools, which is normally not allowed to appear in a hashed dependency
# file.
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

# Filter out errors from modules that do not have Sphinx-compatible
# documentation.
.PHONY: docs
docs:
	tox -e docs | egrep -v ' (fastapi|httpx|pydantic|starlette)\.'
