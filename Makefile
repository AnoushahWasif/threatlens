.PHONY: install lint test hooks

install:
	cd apps/api && uv sync

lint:
	cd apps/api && uv run ruff check . && uv run ruff format --check .

test:
	cd apps/api && uv run pytest

hooks:
	uvx pre-commit install
