.PHONY: install test lint clean

install:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	python -m compileall src

clean:
	rm -rf build dist *.egg-info .pytest_cache
