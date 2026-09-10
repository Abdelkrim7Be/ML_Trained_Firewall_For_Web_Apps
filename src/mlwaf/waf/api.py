"""The console's API.

Mounted under /_waf so it cannot collide with a path on the protected origin: the
proxy claims every other route, so the control plane needs a reserved prefix.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field

from mlwaf.waf import metrics

if TYPE_CHECKING:
    from mlwaf.waf.state import AppState

router = APIRouter(prefix="/_waf", tags=["waf"])

HEARTBEAT_SECONDS = 15.0


def _state(request: Request) -> AppState:
    return request.app.state.waf


# --- health -----------------------------------------------------------------
@router.get("/healthz")
async def healthz() -> dict:
    """Liveness. The process is up; it says nothing about the model."""
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> Response:
    """Readiness. Fails until the model is loaded and warmed.

    Kept distinct from liveness so an orchestrator holds traffic back during
    startup instead of restarting a process that is merely still warming.
    """
    state = _state(request)
    if not state.ready:
        return Response(
            content=json.dumps({"status": "loading"}),
            status_code=503,
            media_type="application/json",
        )
    return Response(
        content=json.dumps({"status": "ready", "threshold": state.engine.threshold}),
        media_type="application/json",
    )


@router.get("/metrics")
async def prometheus() -> Response:
    payload, content_type = metrics.render()
    return Response(content=payload, media_type=content_type)


# --- status and decisions ----------------------------------------------------
@router.get("/status")
async def status(request: Request) -> dict:
    state = _state(request)
    return {
        "mode": state.settings.mode,
        "blocking": state.settings.blocking,
        "threshold": state.engine.threshold,
        "upstream": state.settings.upstream,
        "fail_mode": state.settings.fail_mode,
        "scoring_budget_ms": state.settings.scoring_budget_ms,
        "uptime_seconds": round(time.time() - state.started_at, 1),
        "engine": state.engine.stats,
        "consoles": state.broadcaster.subscriber_count,
        "summary": state.store.summary(),
        "feedback": state.store.feedback_counts(),
    }


@router.get("/decisions")
async def decisions(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    verdict: str | None = Query(None, pattern="^(allow|block)$"),
    attack_class: str | None = Query(None),
    only_flagged: bool = False,
    search: str | None = None,
) -> dict:
    rows = _state(request).store.recent(
        limit=limit, verdict=verdict, attack_class=attack_class,
        only_flagged=only_flagged, search=search,
    )
    return {"decisions": rows}


@router.get("/decisions/{decision_id}")
async def decision_detail(request: Request, decision_id: int) -> dict:
    row = _state(request).store.get(decision_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no such decision")
    return row


@router.get("/traffic")
async def traffic(request: Request, buckets: int = Query(60, ge=10, le=240)) -> dict:
    return {"series": _state(request).store.traffic_series(buckets=buckets)}


# --- threshold ---------------------------------------------------------------
@router.get("/threshold/impact")
async def threshold_impact(
    request: Request,
    value: float = Query(..., ge=0.0, le=1.0),
    window_s: float = Query(3600.0, ge=60.0),
) -> dict:
    """What this threshold would have done to traffic already seen.

    Answered from stored scores, so the operator gets a number computed over real
    requests instead of a promise.
    """
    return _state(request).store.threshold_impact(value, window_s=window_s)


class ThresholdUpdate(BaseModel):
    value: float = Field(ge=0.0, le=1.0)


@router.post("/threshold")
async def set_threshold(request: Request, update: ThresholdUpdate) -> dict:
    state = _state(request)
    state.engine.set_threshold(update.value)
    metrics.THRESHOLD.set(update.value)
    return {"threshold": state.engine.threshold}


class ModeUpdate(BaseModel):
    mode: str = Field(pattern="^(detect|block)$")


@router.post("/mode")
async def set_mode(request: Request, update: ModeUpdate) -> dict:
    state = _state(request)
    state.settings.mode = update.mode
    metrics.MODE.set(1 if state.settings.blocking else 0)
    return {"mode": state.settings.mode, "blocking": state.settings.blocking}


# --- feedback ----------------------------------------------------------------
class Feedback(BaseModel):
    label: str = Field(pattern="^(false_positive|true_positive)$")


@router.post("/decisions/{decision_id}/feedback")
async def feedback(request: Request, decision_id: int, body: Feedback) -> dict:
    state = _state(request)
    ok = await asyncio.to_thread(state.write_feedback, decision_id, body.label)
    if not ok:
        raise HTTPException(status_code=404, detail="no such decision")
    return {"decision_id": decision_id, "label": body.label}


# --- live stream -------------------------------------------------------------
@router.get("/stream")
async def stream(request: Request) -> StreamingResponse:
    state = _state(request)
    queue = state.broadcaster.subscribe()

    async def events():
        try:
            yield ": connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                except TimeoutError:
                    # Keeps intermediaries from closing an idle connection.
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            state.broadcaster.unsubscribe(queue)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
