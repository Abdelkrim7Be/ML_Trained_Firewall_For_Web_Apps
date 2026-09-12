import joblib
import pytest

from mlwaf.waf.config import Settings
from mlwaf.waf.engine import Engine

MODEL = "models/model.joblib"


@pytest.fixture(scope="session")
def bundle():
    try:
        return joblib.load(MODEL)
    except FileNotFoundError:
        pytest.skip(f"{MODEL} missing, run `make train` first")


# Tests assert policy, not how fast this machine happens to be today. A real
# budget belongs in production config; here it would only make the suite flaky
# under load. The one test that exercises the budget sets its own.
TEST_BUDGET_MS = 60_000.0
TEST_TOKEN = "test-admin-token"
AUTH = {"X-MLWAF-Token": TEST_TOKEN}


def make_engine(bundle, **overrides) -> Engine:
    overrides.setdefault("scoring_budget_ms", TEST_BUDGET_MS)
    e = Engine(Settings(**overrides), bundle=dict(bundle))
    e.load()
    return e


@pytest.fixture
def engine(bundle):
    return make_engine(bundle, mode="block")
