.PHONY: help
help:
	@echo "Make targets for Gafaelfawr"
	@echo "make init - Set up dev environment"
	@echo "make update - Update pinned dependencies and run make init"
	@echo "make update-deps - Update pinned dependencies"

.PHONY: init
init:
	uv sync --frozen --all-groups
	uv run prek install

.PHONY: update
update: update-deps init

.PHONY: update-deps
update-deps:
	uv lock --upgrade
	uv lock --upgrade --directory client
	uv run --only-group=lint prek autoupdate
	./scripts/update-uv-version.sh
