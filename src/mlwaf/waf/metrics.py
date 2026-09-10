"""Prometheus metrics.

Enough to answer the three questions an operator asks during an incident: is it
passing traffic, is it blocking anything it should not, and is it slow.
"""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

REQUESTS = Counter(
    "mlwaf_requests_total", "Requests seen by the proxy.", ["verdict", "attack_class"]
)
FLAGGED = Counter(
    "mlwaf_flagged_total",
    "Requests scoring at or above the threshold, whether or not they were refused.",
    ["attack_class"],
)
# Separated from errors on purpose: a request allowed because scoring failed is a
# hole in the firewall, and it must be visible as one rather than buried in a
# success count.
DEGRADED = Counter(
    "mlwaf_degraded_total", "Requests handled without a usable score.", ["reason"]
)
SCORING_SECONDS = Histogram(
    "mlwaf_scoring_seconds",
    "Time to score one request.",
    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0),
)
UPSTREAM_SECONDS = Histogram(
    "mlwaf_upstream_seconds", "Time spent waiting on the protected origin."
)
CACHE_HITS = Counter("mlwaf_cache_hits_total", "Decisions served from the cache.")
THRESHOLD = Gauge("mlwaf_threshold", "Active blocking threshold.")
MODE = Gauge("mlwaf_blocking", "1 when refusing requests, 0 when only observing.")
READY = Gauge("mlwaf_ready", "1 once the model is loaded and warmed.")


def observe(decision) -> None:
    REQUESTS.labels(decision.verdict, decision.attack_class).inc()
    SCORING_SECONDS.observe(decision.latency_ms / 1000.0)
    if decision.would_block:
        FLAGGED.labels(decision.attack_class).inc()
    if decision.degraded:
        DEGRADED.labels(decision.reason).inc()
    if decision.cached:
        CACHE_HITS.inc()


def render() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
