# nbdmux -- common tasks (and the home of the CI logic: the GitHub workflows
# call these targets, so everything CI does is reproducible locally).
# Run `make` for the list. Override vars on the CLI, e.g.
#   make serve PORT=4040            make bump VERSION=0.2.0
PYTHON    ?= python3
RUFF      ?= ruff
PRECOMMIT ?= pre-commit
PORT      ?= 4040
NBD_PORT  ?= 10809
# Containerized deploy: prefer podman, fall back to docker.
COMPOSE   ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker) compose
COMPOSE_FILE = deploy/compose.yml

# Single source of truth = src/nbdmux/__init__.py; pyproject derives it via Hatch.
SRC_VERSION = $(shell sed -n 's/^__version__ = "\(.*\)"/\1/p' src/nbdmux/__init__.py)

.DEFAULT_GOAL := help
.PHONY: help dev hooks-install hooks lint format format-check test \
        wheel serve up down logs version bump check clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# -- dev setup -------------------------------------------------------------
dev: ## Install dev tooling (ruff, build, pre-commit)
	$(PYTHON) -m pip install --upgrade ruff build pre-commit

hooks-install: ## Install the git pre-commit hook
	$(PRECOMMIT) install

hooks: ## Run all pre-commit hooks over the tree
	$(PRECOMMIT) run --all-files

# -- lint / test (CI: lint job, test job) ----------------------------------
lint: ## Lint with ruff
	$(RUFF) check .

format: ## Auto-format with ruff
	$(RUFF) format .

format-check: ## Check formatting (no changes)
	$(RUFF) format --check .

test: ## Run the test suite
	$(PYTHON) -m unittest discover -s tests -v

# -- wheels / sdist --------------------------------------------------------
wheel: ## Build sdist + pure wheel
	$(PYTHON) -m build

# -- run -------------------------------------------------------------------
serve: ## Run nbdmux locally (set NBDMUX_ADMIN_PASSWORD to gate the UI)
	PYTHONPATH=src $(PYTHON) -m nbdmux.server --data-dir ./data --port $(PORT) --nbd-port $(NBD_PORT)

# -- deploy (containerized via compose) ------------------------------------
up: ## Bring up the containerized nbdmux
	$(COMPOSE) -f $(COMPOSE_FILE) up -d --build
	@echo "nbdmux up -> operator UI: http://localhost:$(PORT)/  NBD: tcp://localhost:$(NBD_PORT)"

down: ## Stop and remove the nbdmux container
	$(COMPOSE) -f $(COMPOSE_FILE) down

logs: ## Follow the nbdmux logs
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f

# -- version (single source: src/nbdmux/__init__.py) -----------------------
version: ## Show the version
	@echo "src/nbdmux/__init__.py: $(SRC_VERSION)"

bump: ## Bump the version (usage: make bump VERSION=0.2.0)
	@test -n "$(VERSION)" || { echo "usage: make bump VERSION=X.Y.Z"; exit 2; }
	sed -i 's/^__version__ = ".*"/__version__ = "$(VERSION)"/' src/nbdmux/__init__.py
	@$(MAKE) --no-print-directory version

# -- aggregate / cleanup ---------------------------------------------------
check: lint format-check test ## Everything CI checks, locally

clean: ## Remove build/test artifacts
	rm -rf dist build *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
