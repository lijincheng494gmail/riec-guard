
.PHONY: python-install venv install lock seed-check test lint type-check quality release-scan clean task-note

UV ?= uv
PYTHON_VERSION := 3.12.13
VENV := .venv
PYTHON := $(VENV)/bin/python

python-install:
	$(UV) python install $(PYTHON_VERSION)

venv: python-install
	$(UV) venv --python $(PYTHON_VERSION) --clear $(VENV)

install: venv
	$(UV) pip sync --python $(PYTHON) --require-hashes requirements.lock
	$(UV) pip install --python $(PYTHON) --no-deps --editable .

lock:
	$(UV) pip compile requirements.in --python-version $(PYTHON_VERSION) --universal --generate-hashes --custom-compile-command "make lock" --output-file requirements.lock

seed-check:
	$(PYTHON) scripts/validate_seed.py

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check src scripts tests streamlit_app.py

type-check:
	$(PYTHON) -m mypy src scripts tests streamlit_app.py

quality: seed-check test lint type-check

release-scan: clean
	$(UV) run --isolated --no-project --python $(PYTHON_VERSION) python scripts/public_release_scan.py .

clean:
	rm -rf $(VENV)

task-note:
	@echo "Open the Phase E command pack and execute only the next unblocked task."
