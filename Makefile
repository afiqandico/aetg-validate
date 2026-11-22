# Prefer the project venv when present so `make` works without activating it.
PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
export PYTHONPATH := src

.PHONY: help install demo test verify clean

help:
	@echo "make install  - editable install with dev extras"
	@echo "make test     - run the test suite"
	@echo "make demo     - deterministic synthetic scan"
	@echo "make verify   - full gate: tests + demo + digest re-verification"

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

demo:
	$(PY) -m aetg_validate demo --out aetg-demo-report

verify: test demo
	@echo "--- re-rendering saved scan and checking integrity ---"
	$(PY) -m aetg_validate report --scan aetg-demo-report/scan.json --out aetg-demo-report/verify
	@echo "VERIFY OK"

clean:
	rm -rf aetg-demo-report aetg-report aetg-report-rendered
	rm -rf .pytest_cache **/__pycache__ src/*.egg-info
