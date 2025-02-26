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
	uv sync --frozen --all-groups
	uv run pre-commit install
	cd ui && npm install --force

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
	uv lock --upgrade
	uv run --only-group=lint pre-commit autoupdate
	cd ui && npm upgrade --legacy-peer-deps
