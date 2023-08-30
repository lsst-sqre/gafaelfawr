.PHONY: help
help:
	@echo "Make targets for Gafaelfawr"
	@echo "make init - Set up dev environment"
	@echo "make linkcheck - Check for broken links in documentation"
	@echo "make ui - Build the JavaScript frontend"
	@echo "make update - Update pinned dependencies and run make init"
	@echo "make update-deps - Update pinned dependencies"
	@echo "make update-deps-no-hashes - Pin dependencies without hashes"

# npm dependencies have to be installed for pre-commit eslint to work.
.PHONY: init
init:
	pip install --editable .
	pip install --upgrade -r requirements/main.txt -r requirements/dev.txt
	rm -rf .tox
	pip install --upgrade tox tox-docker
	pre-commit install
	cd ui && npm install --legacy-peer-deps

# This is defined as a Makefile target instead of only a tox command because
# if the command fails we want to cat output.txt, which contains the
# actually useful linkcheck output. tox unfortunately doesn't support this
# level of shell trickery after failed commands.
.PHONY: linkcheck
linkcheck:
	sphinx-build --keep-going -n -W -T -b linkcheck docs	\
	    docs/_build/linkcheck				\
	    || (cat docs/_build/linkcheck/output.txt; exit 1)

.PHONY: ui
ui:
	cd ui && npm run lint:fix
	cd ui && npm run build

.PHONY: update
update: update-deps init

# The dependencies need --allow-unsafe because kubernetes-asyncio and
# (transitively) pre-commit depends on setuptools, which is normally not
# allowed to appear in a hashed dependency file.
.PHONY: update-deps
update-deps:
	pip install --upgrade pip-tools pip setuptools
	pip-compile --upgrade --resolver=backtracking --build-isolation	\
	    --allow-unsafe --generate-hashes				\
	    --output-file requirements/main.txt requirements/main.in
	pip-compile --upgrade --resolver=backtracking --build-isolation	\
	    --allow-unsafe --generate-hashes				\
	    --output-file requirements/dev.txt requirements/dev.in

# Useful for testing against a Git version of Safir.
.PHONY: update-deps-no-hashes
update-deps-no-hashes:
	pip install --upgrade pip-tools pip setuptools
	pip-compile --upgrade --resolver=backtracking --build-isolation	\
	    --allow-unsafe						\
	    --output-file requirements/main.txt requirements/main.in
	pip-compile --upgrade --resolver=backtracking --build-isolation	\
	    --allow-unsafe						\
	    --output-file requirements/dev.txt requirements/dev.in
