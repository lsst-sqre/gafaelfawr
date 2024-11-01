.PHONY: help
help:
	@echo "Make targets for Gafaelfawr"
	@echo "make init - Set up dev environment"
	@echo "make linkcheck - Check for broken links in documentation"
	@echo "make ui - Build the JavaScript frontend"
	@echo "make update - Update pinned dependencies and run make init"
	@echo "make update-deps - Update pinned dependencies"

.PHONY: init
init:
	pip install --upgrade uv
	uv pip install --verify-hashes -r requirements/main.txt \
	    -r requirements/dev.txt -r requirements/tox.txt
	uv pip install --editable .
	rm -rf .tox
	uv pip install --upgrade pre-commit
	pre-commit install
	cd ui && npm install --legacy-peer-deps

# This is defined as a Makefile target instead of only a tox command because
# if the command fails we want to cat output.txt, which contains the
# actually useful linkcheck output. tox unfortunately doesn't support this
# level of shell trickery after failed commands.
.PHONY: linkcheck
linkcheck:
	sphinx-build -W --keep-going -n -T -b linkcheck docs	\
	    docs/_build/linkcheck				\
	    || (cat docs/_build/linkcheck/output.txt; exit 1)

.PHONY: ui
ui:
	cd ui && npm run lint:fix
	cd ui && npm run build

.PHONY: update
update: update-deps init

.PHONY: update-deps
update-deps:
	pip install --upgrade pip uv
	uv pip install --upgrade pre-commit
	pre-commit autoupdate
	uv pip compile --upgrade --generate-hashes --universal		\
	    --output-file requirements/main.txt pyproject.toml
	uv pip compile --upgrade --generate-hashes --universal		\
	    --output-file requirements/dev.txt requirements/dev.in
	uv pip compile --upgrade --generate-hashes --universal		\
	    --output-file requirements/tox.txt requirements/tox.in
	cd ui && npm upgrade --legacy-peer-deps
