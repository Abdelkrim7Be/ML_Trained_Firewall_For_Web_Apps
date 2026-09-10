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


@pytest.fixture
def engine(bundle):
    e = Engine(Settings(mode="block"), bundle=dict(bundle))
    e.load()
    return e
