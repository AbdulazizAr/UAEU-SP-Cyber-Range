.PHONY: setup lint fmt types test arch check schemas refs

setup:            ## create the venv and install everything (needs internet once)
	uv sync --all-groups
	uv run pre-commit install

fmt:
	uv run ruff format .
	uv run ruff check --fix .

lint:
	uv run ruff check .
	uv run ruff format --check .

types:
	uv run mypy

arch:             ## real-clock ban + import boundaries
	uv run python -m iris.devtools.boundaries src

test:
	uv run pytest
	uv run python -m doctest src/iris/core/vclock.py

check: lint types arch test   ## everything CI runs
	uv run iris spec validate examples/*.spec.yaml

schemas:          ## JSON Schemas for the Engine team
	uv run iris schema export

refs:             ## download + pin references, then verify
	uv run iris refs fetch
	uv run iris refs verify
