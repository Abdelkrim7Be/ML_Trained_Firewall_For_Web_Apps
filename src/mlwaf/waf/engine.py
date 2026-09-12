"""Scoring and the decision that follows from it.

This is the only place that decides whether a request is refused. The proxy asks
it a question and does what it says; keeping the policy here means the failure
paths, the cache and the latency budget are all testable without a socket.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

import joblib

from mlwaf.decode import request_parts
from mlwaf.model import CLASSES, attack_score
from mlwaf.units import decompose
from mlwaf.waf.config import Settings, get_settings
from mlwaf.waf.scorer import FastScorer

log = logging.getLogger("mlwaf.engine")

ALLOW, BLOCK = "allow", "block"


@dataclass
class Decision:
    """What the engine concluded, and enough context to explain it later."""

    verdict: str
    would_block: bool
    score: float
    attack_class: str
    threshold: float
    latency_ms: float
    cached: bool = False
    degraded: bool = False
    reason: str = "scored"
    probabilities: dict[str, float] = field(default_factory=dict)
    canonical_text: str = ""
    decode_depth: int = 0
    # Which part of the request was worst, when scoring per unit.
    worst_unit: str = ""
    unit_count: int = 0

    @property
    def blocked(self) -> bool:
        return self.verdict == BLOCK


@dataclass
class RequestView:
    """The parts of an HTTP request the model is allowed to see.

    Host, cookies and user agent are carried for the audit log but deliberately
    kept out of the scored text: during training they identified the corpus rather
    than the attack, and the same trap exists in production, where they would
    identify the client rather than the payload.
    """

    method: str
    path: str
    query: str
    body: str
    headers: dict[str, str] = field(default_factory=dict)

    def canonical(self) -> tuple[str, str, int]:
        return request_parts(self.method, self.path, self.query, self.body)


class _LRU(OrderedDict):
    """Most traffic repeats. Scoring it twice is waste."""

    def __init__(self, capacity: int):
        super().__init__()
        self.capacity = max(capacity, 1)

    def get_(self, key: str) -> Any | None:
        if key not in self:
            return None
        self.move_to_end(key)
        return self[key]

    def put(self, key: str, value: Any) -> None:
        self[key] = value
        self.move_to_end(key)
        while len(self) > self.capacity:
            self.popitem(last=False)


class Engine:
    def __init__(self, settings: Settings | None = None, bundle: dict | None = None):
        self.settings = settings or get_settings()
        self._bundle = bundle
        self._scorer: FastScorer | None = None
        self._cache = _LRU(self.settings.cache_size)
        # guards cache/stats: decide() runs concurrently, one thread per request
        self._lock = threading.Lock()
        self.ready = False
        # A model trained on individual values expects to be given individual
        # values. The bundle records which it is, so a request level model and a
        # unit level model can both be served without a flag being set wrongly.
        self.unit_mode = bool((bundle or {}).get("unit_mode", False))
        self.stats = {"scored": 0, "cached": 0, "timeouts": 0, "errors": 0}

    # --- lifecycle -----------------------------------------------------------
    def load(self) -> None:
        """Load and warm the model. Readiness stays false until this returns."""
        if self._bundle is None:
            self._bundle = joblib.load(self.settings.model_path)
        if self.settings.threshold is not None:
            self._bundle["threshold"] = self.settings.threshold
        self._scorer = FastScorer(self._bundle["pipeline"])
        self.unit_mode = bool(self._bundle.get("unit_mode", False))

        self._warm()
        self.ready = True
        log.info(
            "model loaded", extra={"path": self.settings.model_path,
                                   "threshold": self.threshold}
        )

    def _warm(self) -> None:
        """Score a few representative requests before accepting traffic.

        The first prediction through any given code path is far slower than the
        rest: vocabulary lookups, sparse allocation and the booster's first walk
        all pay a one time cost. Scoring a single trivial request is not enough to
        cover that, and the symptom is the first real request of the day blowing
        through the latency budget and being allowed through unscored. So warm
        with something from each shape: benign, injection, script, and a body.
        """
        for view in (
            RequestView("GET", "/", "", ""),
            RequestView("GET", "/products/search", "q=running+shoes", ""),
            RequestView("GET", "/item", "id=1%27+OR+1%3D1--", ""),
            RequestView("GET", "/search", "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", ""),
            RequestView("POST", "/login", "", "username=admin&password=hunter2"),
        ):
            self._score(view)

    @property
    def threshold(self) -> float:
        if not self._bundle:
            return 1.0
        return float(self._bundle["threshold"])

    def set_threshold(self, value: float) -> None:
        """Used by the console. Changing it invalidates cached verdicts."""
        if self._bundle:
            self._bundle["threshold"] = float(value)
        with self._lock:
            self._cache.clear()

    # --- scoring -------------------------------------------------------------
    def _score_text(self, text: str, url_text: str, body_text: str,
                    query: str, path: str, depth: int):
        proba = self._scorer.score(text, url_text, body_text, query, path, depth)
        return float(attack_score(proba.reshape(1, -1))[0]), proba

    def _score(self, view: RequestView) -> tuple[float, str, dict[str, float], str, int, str, int]:
        if self.unit_mode:
            return self._score_units(view)

        url_text, body_text, depth = view.canonical()
        text = "\n".join(t for t in (url_text, body_text) if t)
        score, proba = self._score_text(text, url_text, body_text,
                                        view.query, view.path, depth)
        probabilities = {c: round(float(p), 6) for c, p in zip(CLASSES, proba)}
        attack_class = max(CLASSES[1:], key=lambda c: probabilities[c])
        return score, attack_class, probabilities, text, depth, "request", 1

    def _score_units(self, view: RequestView):
        """Score each value on its own and take the worst.

        An injection lives in one parameter. Scoring the request as a whole makes
        the surrounding context part of the evidence, which is how a model ends up
        deciding that Spanish checkout parameters look like an attack. Scoring
        values independently removes the context, and incidentally removes the
        dilution evasion: padding a query with junk parameters just adds more
        benign units.
        """
        units = decompose(view.method, view.path, view.query, view.body)

        worst_score, worst_proba, worst_text, worst_label, worst_depth = -1.0, None, "", "", 0
        for unit in units:
            text = unit.text()
            if not text:
                continue
            depth = unit.depth()
            score, proba = self._score_text(text, text, "", unit.value, "", depth)
            if score > worst_score:
                worst_score, worst_proba = score, proba
                worst_text, worst_depth = text, depth
                worst_label = f"{unit.kind}:{unit.name}" if unit.name else unit.kind

        if worst_proba is None:
            return 0.0, "unknown", {c: 0.0 for c in CLASSES}, "", 0, "", 0

        probabilities = {c: round(float(p), 6) for c, p in zip(CLASSES, worst_proba)}
        attack_class = max(CLASSES[1:], key=lambda c: probabilities[c])
        return (worst_score, attack_class, probabilities, worst_text, worst_depth,
                worst_label, len(units))

    def decide(self, view: RequestView) -> Decision:
        started = time.perf_counter()
        key = hashlib.sha1(
            f"{view.method}\n{view.path}\n{view.query}\n{view.body}".encode()
        ).hexdigest()

        with self._lock:
            cached = self._cache.get_(key)
        if cached is not None:
            with self._lock:
                self.stats["cached"] += 1
            return self._verdict(cached, time.perf_counter() - started, cached_hit=True)

        try:
            score, attack_class, probabilities, text, depth, worst, n_units = \
                self._score(view)
        except Exception:
            # A model that raises must not take the site down with it.
            with self._lock:
                self.stats["errors"] += 1
            log.exception("scoring failed")
            return self._degraded(started, "scoring_error")

        elapsed_ms = (time.perf_counter() - started) * 1000
        if elapsed_ms > self.settings.scoring_budget_ms:
            # The answer arrived, but too late to be worth trusting as a gate.
            # Count it, let the request through, keep the score for the log.
            with self._lock:
                self.stats["timeouts"] += 1
            log.warning("scoring exceeded budget", extra={"ms": round(elapsed_ms, 2)})

        payload = {
            "score": score,
            "attack_class": attack_class,
            "probabilities": probabilities,
            "canonical_text": text,
            "decode_depth": depth,
            "worst_unit": worst,
            "unit_count": n_units,
            "over_budget": elapsed_ms > self.settings.scoring_budget_ms,
        }
        with self._lock:
            self._cache.put(key, payload)
            self.stats["scored"] += 1
        return self._verdict(payload, time.perf_counter() - started)

    # --- policy --------------------------------------------------------------
    def _verdict(self, payload: dict, elapsed_s: float, cached_hit: bool = False) -> Decision:
        score = payload["score"]
        would_block = score >= self.threshold
        over_budget = payload.get("over_budget", False)

        # would_block is recorded even when nothing is enforced. That is what
        # detect mode is for, and what the review queue reads.
        if over_budget:
            verdict, reason = ALLOW, "over_budget"
        elif not self.settings.blocking:
            verdict, reason = ALLOW, "detect_mode"
        else:
            verdict = BLOCK if would_block else ALLOW
            reason = "scored"

        return Decision(
            verdict=verdict,
            would_block=would_block,
            score=score,
            attack_class=payload["attack_class"],
            threshold=self.threshold,
            latency_ms=round(elapsed_s * 1000, 3),
            cached=cached_hit,
            degraded=over_budget,
            reason=reason,
            probabilities=payload["probabilities"],
            canonical_text=payload["canonical_text"],
            decode_depth=payload["decode_depth"],
            worst_unit=payload.get("worst_unit", ""),
            unit_count=payload.get("unit_count", 0),
        )

    def _degraded(self, started: float, reason: str) -> Decision:
        """No usable score. Behaviour here is the fail policy, and it is explicit."""
        verdict = ALLOW if self.settings.fail_open else BLOCK
        return Decision(
            verdict=verdict,
            would_block=False,
            score=0.0,
            attack_class="unknown",
            threshold=self.threshold,
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            degraded=True,
            reason=reason,
        )
