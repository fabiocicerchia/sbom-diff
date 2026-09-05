.PHONY: help setup install dev lint format test build run analyze

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

setup: ## Install the pre-commit hook
	pre-commit install

install: ## Install the package
	pip install .

dev: ## Editable install with dev dependencies
	pip install -e ".[dev]"

lint: ## Run the whole gate — every hook, every file
	pre-commit run --all-files

format: ## Format code with ruff
	ruff format .

test: ## Run tests
	pytest -q

build: ## Build sdist and wheel
	python -m build

run: ## Run sbom-diff
	sbom-diff --help

analyze: ## Type-check the package
	basedpyright
