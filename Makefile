.PHONY: help setup install dev lint format test build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

setup: ## Install git hooks and pre-commit
	git config core.hooksPath .githooks
	@command -v pre-commit >/dev/null 2>&1 && pre-commit install || true

install: ## Install the package
	pip install .

dev: ## Editable install with dev dependencies
	pip install -e ".[dev]"

lint: ## Run ruff checks
	ruff check .

format: ## Format code with ruff
	ruff format .

test: ## Run tests
	pytest -q

build: ## Build sdist and wheel
	python -m build
