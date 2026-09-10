VENV := .venv/bin

.PHONY: install data train plots report test e2e lint notebook benchmark \
        robustness errors adversarial external stability all evaluate clean

install:
	uv venv --python 3.12
	uv pip install -e ".[dev,train,waf]"

data:
	$(VENV)/python -m mlwaf.download
	$(VENV)/python -m mlwaf.dataset

train:
	$(VENV)/python -m mlwaf.train

# --- evaluation -------------------------------------------------------------
robustness:            ## recall decay under 13 obfuscation transforms
	$(VENV)/python -m mlwaf.robustness

errors:                ## profile what the model misses
	$(VENV)/python -m mlwaf.errors

external:              ## 646 third-party obfuscated payloads
	$(VENV)/python -m mlwaf.external

adversarial:           ## train on 4 transforms, score on 9 held out
	$(VENV)/python -m mlwaf.adversarial

benchmark:             ## score against a real web server trace and outside payloads
	$(VENV)/python -m mlwaf.waf.benchmark

stability:             ## refit across 5 seeds; slow, run before design changes
	$(VENV)/python -m mlwaf.stability

plots:
	$(VENV)/python -m mlwaf.plots

report:                ## regenerate reports/tables.md from the JSON
	$(VENV)/python -m mlwaf.report

evaluate: robustness errors external adversarial plots report

# --- quality ----------------------------------------------------------------
test:                  ## unit and integration
	$(VENV)/python -m pytest tests/waf tests/test_*.py -q

e2e:                   ## end to end, starts real server processes
	$(VENV)/python -m pytest tests/e2e -q

lint:
	$(VENV)/ruff check src tests

notebook:
	$(VENV)/jupyter notebook notebooks/

all: data train evaluate test e2e

clean:
	rm -rf data/processed/* reports/*.png reports/*.json reports/tables.md models/*.joblib
	git checkout -- reports/robustness_baseline.json 2>/dev/null || true
