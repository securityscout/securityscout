.PHONY: install format lint typecheck test testcov testslow check all clean

install:
	uv sync --dev
	uv run pre-commit install

format:
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

lint:
	uv run ruff check src/ tests/
	uv run ruff format --check src/ tests/

typecheck:
	uv run mypy src/

test:
	uv run pytest -x -n auto

testcov:
	uv run pytest -x -n auto --cov=src --cov-report=term-missing

testslow:
	uv run pytest -m slow

check: lint typecheck testcov

all: format check

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache htmlcov .coverage coverage.xml dist/
	find . -type d -name __pycache__ -exec rm -rf {} +
