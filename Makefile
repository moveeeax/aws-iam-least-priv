.PHONY: install test lint clean

install:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check src tests

clean:
	rm -rf build dist *.egg-info .pytest_cache
