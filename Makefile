.PHONY: help setup install dev lint format test build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

setup: ## Install the pre-commit hook
	pre-commit install

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
