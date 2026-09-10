"""The decision path, especially the ways it is allowed to fail."""

import pytest

from mlwaf.waf.config import Settings
from mlwaf.waf.engine import ALLOW, BLOCK, Engine, RequestView

SQLI = RequestView("GET", "/item", "id=1%27+UNION+SELECT+password+FROM+users--", "")
XSS = RequestView("GET", "/search", "q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E", "")
BENIGN = RequestView("GET", "/products/search", "q=running+shoes", "")
BENIGN_QUOTE = RequestView("POST", "/account", "", "name=O'Brien&city=Cork")


def test_blocks_sql_injection(engine):
    d = engine.decide(SQLI)
    assert d.verdict == BLOCK
    assert d.attack_class == "sqli"
    assert d.score >= d.threshold


def test_blocks_xss(engine):
    d = engine.decide(XSS)
    assert d.verdict == BLOCK
    assert d.attack_class == "xss"


def test_allows_benign(engine):
    assert engine.decide(BENIGN).verdict == ALLOW


def test_allows_apostrophe_in_a_name(engine):
    """The request v0 blocked, along with half of all legitimate traffic."""
    d = engine.decide(BENIGN_QUOTE)
    assert d.verdict == ALLOW
    assert d.score < 0.5


def test_detect_mode_records_intent_without_enforcing(bundle):
    e = Engine(Settings(mode="detect"), bundle=dict(bundle))
    e.load()
    d = e.decide(SQLI)
    assert d.verdict == ALLOW          # nothing is refused
    assert d.would_block is True       # but the intent is recorded
    assert d.reason == "detect_mode"


def test_cache_returns_the_same_verdict(engine):
    first = engine.decide(SQLI)
    second = engine.decide(SQLI)
    assert second.cached is True
    assert second.verdict == first.verdict
    assert engine.stats["cached"] == 1


def test_raising_model_fails_open_by_default(bundle):
    e = Engine(Settings(mode="block", fail_mode="open"), bundle=dict(bundle))
    e.load()
    e._scorer = _Exploding()
    d = e.decide(SQLI)
    assert d.verdict == ALLOW
    assert d.degraded is True
    assert d.reason == "scoring_error"
    assert e.stats["errors"] == 1


def test_raising_model_can_fail_closed(bundle):
    e = Engine(Settings(mode="block", fail_mode="closed"), bundle=dict(bundle))
    e.load()
    e._scorer = _Exploding()
    assert e.decide(SQLI).verdict == BLOCK


def test_exceeding_the_latency_budget_allows_the_request(bundle):
    """A slow model must cost protection, never availability."""
    e = Engine(Settings(mode="block", scoring_budget_ms=0.0), bundle=dict(bundle))
    e.load()
    d = e.decide(SQLI)
    assert d.verdict == ALLOW
    assert d.reason == "over_budget"
    assert d.would_block is True       # the score still says what it says
    assert e.stats["timeouts"] == 1


def test_threshold_change_clears_the_cache(engine):
    engine.decide(BENIGN)
    engine.set_threshold(0.0)
    d = engine.decide(BENIGN)
    assert d.cached is False
    assert d.verdict == BLOCK          # everything is an attack at threshold 0


def test_not_ready_until_loaded(bundle):
    e = Engine(Settings(), bundle=dict(bundle))
    assert e.ready is False
    e.load()
    assert e.ready is True


def test_probabilities_sum_to_one(engine):
    d = engine.decide(SQLI)
    assert pytest.approx(sum(d.probabilities.values()), abs=1e-6) == 1.0


class _Exploding:
    """Stands in for the serving path when the question is what happens if it dies."""

    def score(self, *_args, **_kwargs):
        raise RuntimeError("model is broken")
