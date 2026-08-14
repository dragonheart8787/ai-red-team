PY := .venv/bin/python
PIP := .venv/bin/pip
PYTEST := .venv/bin/pytest

.PHONY: setup db test test-py test-opa lint clean

setup:
	python3.12 -m venv .venv
	$(PIP) install -q --upgrade pip
	$(PIP) install -q -e '.[dev]'

db:
	./scripts/init_db.sh

test: test-opa test-py

test-py:
	$(PYTEST) -q

test-opa:
	opa test control_plane/policy/rego policy_tests -v

lint:
	.venv/bin/ruff check .

clean:
	rm -rf .venv .pytest_cache **/__pycache__
