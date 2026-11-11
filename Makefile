# Developer shortcuts. `make` on Linux/macOS, `make.ps1` equivalent on Windows.
.DEFAULT_GOAL := help
PY ?= python3
SRC := src
PKG := src/netscan

.PHONY: help install install-dev test test-fast lint format type check build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install the package
	$(PY) -m pip install .

install-dev: ## Install the package with test and lint tooling
	$(PY) -m pip install -e ".[dev]"

test: ## Run the full suite with coverage
	$(PY) -m pytest -q --cov=netscan --cov-report=term-missing

test-fast: ## Run the suite and stop at the first failure
	$(PY) -m pytest -q -x --no-header

lint: ## Ruff
	$(PY) -m ruff check $(PKG) tests Network-scanner.py

format: ## Ruff format
	$(PY) -m ruff format $(PKG) tests

type: ## Mypy strict
	$(PY) -m mypy $(PKG)

check: lint type test ## Everything CI runs

build: clean ## Build sdist and wheel
	$(PY) -m build

clean: ## Remove build and cache artefacts
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
