"""Everything the request path needs, assembled once at startup."""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import joblib

from mlwaf.model import CLASSES
from mlwaf.waf import metrics
from mlwaf.waf.config import Settings, get_settings
from mlwaf.waf.engine import Engine, RequestView
from mlwaf.waf.explain import Explainer
from mlwaf.waf.security import generate_token
from mlwaf.waf.store import DecisionRecord, Store

log = logging.getLogger("mlwaf.state")

BODY_PREVIEW_CHARS = 500
EXPLAIN_SCORE_FLOOR = 0.10


class Broadcaster:
    """Fans decisions out to connected consoles.

    Each subscriber gets a bounded queue. A console that cannot keep up drops
    events rather than growing a queue without limit, because the dashboard
    falling behind must never apply backpressure to the request path.
    """

    def __init__(self, maxsize: int = 256):
        self._subscribers: set[asyncio.Queue] = set()
        self._maxsize = maxsize

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._maxsize)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def publish(self, event: dict[str, Any]) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


class AppState:
    def __init__(self, settings: Settings | None = None, bundle: dict | None = None):
        self.settings = settings or get_settings()
        self.engine = Engine(self.settings, bundle=bundle)
        self.store = Store(self.settings.db_path, self.settings.retention_rows)
        self.broadcaster = Broadcaster()
        self.client: httpx.AsyncClient | None = None
        self.explainer: Explainer | None = None
        self.started_at = time.time()
        self._ids = itertools.count(1)
        self._boot = uuid.uuid4().hex[:8]

    # --- lifecycle -----------------------------------------------------------
    async def startup(self) -> None:
        if not self.settings.admin_token:
            # A generated token still protects the control plane; printing it is
            # what keeps a local run usable without any configuration.
            self.settings.admin_token = generate_token()
            log.warning(
                "no WAF_ADMIN_TOKEN set, generated one for this run",
                extra={"admin_token": self.settings.admin_token},
            )
        self.store.connect()
        # Blocking work, kept off the event loop so startup does not stall it.
        await asyncio.to_thread(self.engine.load)
        self.explainer = Explainer(self.engine._bundle["pipeline"], self.engine._scorer)
        self.client = httpx.AsyncClient(
            timeout=self.settings.upstream_timeout_s,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )
        metrics.THRESHOLD.set(self.engine.threshold)
        metrics.MODE.set(1 if self.settings.blocking else 0)
        metrics.READY.set(1)
        log.info(
            "waf ready",
            extra={"upstream": self.settings.upstream, "mode": self.settings.mode,
                   "threshold": self.engine.threshold},
        )

    async def shutdown(self) -> None:
        metrics.READY.set(0)
        if self.client is not None:
            await self.client.aclose()
        self.store.close()

    @property
    def ready(self) -> bool:
        return self.engine.ready and self.client is not None

    def next_request_id(self) -> str:
        return f"{self._boot}-{next(self._ids):08d}"

    # --- recording -----------------------------------------------------------
    async def record(self, request, decision, request_id: str,
                     body: str = "") -> None:
        metrics.observe(decision)

        # Explaining costs a second pass through the booster, so it is reserved
        # for requests that are actually interesting. Nobody needs SHAP values
        # for a stylesheet.
        explanation: dict[str, Any] = {}
        if decision.score >= EXPLAIN_SCORE_FLOOR and self.explainer is not None:
            view = RequestView(
                request.method, request.url.path, request.url.query or "", body
            )
            try:
                index = CLASSES.index(decision.attack_class)
            except ValueError:
                index = 1
            try:
                explanation = await asyncio.to_thread(
                    self.explainer.explain, view, decision, index
                )
            except Exception:
                log.exception("explanation failed", extra={"request_id": request_id})

        record = DecisionRecord(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query=request.url.query or "",
            body_preview=body[:BODY_PREVIEW_CHARS],
            client=request.client.host if request.client else "",
            verdict=decision.verdict,
            would_block=decision.would_block,
            score=decision.score,
            attack_class=decision.attack_class,
            threshold=decision.threshold,
            latency_ms=decision.latency_ms,
            cached=decision.cached,
            degraded=decision.degraded,
            reason=decision.reason,
            decode_depth=decision.decode_depth,
            canonical=decision.canonical_text[:2000],
            explanation=explanation,
        )
        row_id = await asyncio.to_thread(self.store.insert, record)

        self.broadcaster.publish({
            "id": row_id,
            "request_id": request_id,
            "ts": record.ts,
            "method": record.method,
            "path": record.path,
            "query": record.query[:300],
            "verdict": record.verdict,
            "would_block": record.would_block,
            "score": round(record.score, 4),
            "attack_class": record.attack_class,
            "latency_ms": record.latency_ms,
            "degraded": record.degraded,
            "reason": record.reason,
        })

    # --- feedback ------------------------------------------------------------
    def write_feedback(self, decision_id: int, label: str) -> bool:
        """Record a verdict correction, and append it where training can read it.

        The file is JSON lines in the shape the training pipeline already expects,
        so the loop back to the model is a file rather than an integration.
        """
        row = self.store.get(decision_id)
        if row is None:
            return False
        self.store.set_feedback(decision_id, label)

        path = Path(self.settings.feedback_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": time.time(),
                "decision_id": decision_id,
                "label": label,
                "method": row["method"],
                "path": row["path"],
                "query": row["query"],
                "canonical": row["canonical"],
                "score": row["score"],
                "predicted_class": row["attack_class"],
            }) + "\n")
        return True


def load_bundle(settings: Settings) -> dict:
    return joblib.load(settings.model_path)
