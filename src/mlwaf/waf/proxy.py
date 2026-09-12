"""The reverse proxy.

Sits in front of one origin, scores every request, and either forwards it or
refuses it. This is the part v0 never had: it printed "Intrusion Detected !" and
then proxied the request anyway.

Everything the engine needs is extracted here: method, path, query, body, headers
and cookies. v0 read GET paths only, which meant POST bodies, where most SQL
injection actually travels, were never looked at.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from mlwaf.waf.engine import Decision, RequestView

if TYPE_CHECKING:
    from mlwaf.waf.state import AppState

log = logging.getLogger("mlwaf.proxy")

router = APIRouter()

# Hop by hop headers belong to a single connection and must not be relayed.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})


def _decoded_body(raw: bytes, limit: int) -> tuple[str, bool]:
    """Text of the body for scoring, and whether it was too large to score.

    Oversized bodies are forwarded untouched rather than buffered. A proxy that
    holds unbounded uploads in memory to inspect them is a denial of service
    waiting to be discovered.
    """
    if len(raw) > limit:
        return "", True
    return raw.decode("utf-8", errors="replace"), False


def _view(request: Request, body: str) -> RequestView:
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP
    }
    return RequestView(
        method=request.method,
        path=request.url.path,
        query=request.url.query or "",
        body=body,
        headers=headers,
    )


def _blocked_response(decision: Decision, request_id: str) -> JSONResponse:
    """A refusal says enough to debug and nothing that helps tune an attack."""
    return JSONResponse(
        status_code=403,
        content={
            "error": "request_blocked",
            "message": "This request was refused by the web application firewall.",
            "request_id": request_id,
        },
        headers={
            "X-MLWAF-Request-Id": request_id,
            "X-MLWAF-Action": "block",
        },
    )


async def _forward(state: AppState, request: Request, raw_body: bytes) -> Response:
    url = httpx.URL(
        state.settings.upstream + request.url.path,
        query=request.url.query.encode() if request.url.query else None,
    )
    headers = [
        (k, v) for k, v in request.headers.raw
        if k.decode().lower() not in HOP_BY_HOP and k.decode().lower() != "host"
    ]

    upstream = await state.client.request(
        request.method, url, headers=headers, content=raw_body,
    )
    response_headers = {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in HOP_BY_HOP and k.lower() != "content-length"
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
    )


@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def proxy(request: Request) -> Response:
    state: AppState = request.app.state.waf
    request_id = request.headers.get("x-request-id") or state.next_request_id()

    raw_body = await request.body()
    body, oversized = _decoded_body(raw_body, state.settings.max_body_bytes)

    # Scoring is synchronous CPU work. Running it inline blocks the event loop
    # for the duration, so concurrent requests queue behind each other and start
    # timing out well before the model is actually saturated. numpy and LightGBM
    # release the GIL for the expensive parts, so a worker thread genuinely
    # overlaps rather than just moving the problem.
    decision = await asyncio.to_thread(state.engine.decide, _view(request, body))
    if oversized:
        # Recorded honestly: this request was forwarded without being scored.
        decision.reason = "body_too_large"
        decision.degraded = True
        decision.verdict = "allow"

    await state.record(request, decision, request_id, body=body)

    if decision.blocked:
        log.warning(
            "blocked",
            extra={"request_id": request_id, "path": request.url.path,
                   "score": decision.score, "class": decision.attack_class},
        )
        return _blocked_response(decision, request_id)

    try:
        response = await _forward(state, request, raw_body)
    except httpx.TimeoutException:
        return JSONResponse(
            status_code=504,
            content={"error": "upstream_timeout", "request_id": request_id},
        )
    except httpx.HTTPError:
        log.exception("upstream failed", extra={"request_id": request_id})
        return JSONResponse(
            status_code=502,
            content={"error": "upstream_unavailable", "request_id": request_id},
        )

    response.headers["X-MLWAF-Request-Id"] = request_id
    if decision.would_block and not decision.blocked:
        # Detect mode. The operator can see what enforcement would have done
        # without the site behaving any differently.
        response.headers["X-MLWAF-Action"] = "would-block"
    return response
