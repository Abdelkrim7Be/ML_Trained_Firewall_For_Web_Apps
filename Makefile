VENV := .venv/bin

.PHONY: install data train plots test lint all clean

install:
	uv venv --python 3.12
	uv pip install -e ".[dev]"

data:
	$(VENV)/python -m mlwaf.download
	$(VENV)/python -m mlwaf.dataset

train:
	$(VENV)/python -m mlwaf.train

plots:
	$(VENV)/python -m mlwaf.plots

test:
	$(VENV)/python -m pytest tests/ -q

lint:
	$(VENV)/ruff check src tests

notebook:
	$(VENV)/jupyter notebook notebooks/

all: data train plots test

clean:
	rm -rf data/processed/* reports/*.png reports/*.json models/*.joblib
