"""Access control for the control plane.

The proxy and the console share a port, by design: one process, one thing to
deploy. The cost of that choice is that every client of the protected application
can also reach `/_waf`, so the control plane has to authenticate.

Liveness and readiness stay open. An orchestrator has to be able to poll them, and
they reveal nothing an attacker cannot learn by sending a request.
"""

from __future__ import annotations

import hmac
import logging
import secrets

from fastapi import Depends, HTTPException, Request, status

log = logging.getLogger("mlwaf.security")

HEADER = "X-MLWAF-Token"


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def _presented(request: Request) -> str | None:
    """Accept a bearer header, the console's header, or a query parameter.

    The query parameter exists for one reason: EventSource cannot set headers, so
    the live stream has no other way to authenticate. It is narrower than it
    looks, since the value travels inside the same TLS connection a header would,
    but it does end up in access logs, so it is accepted only here and the token
    should be rotated if those logs are shared.
    """
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    header = request.headers.get(HEADER)
    if header:
        return header
    return request.query_params.get("token")


def require_admin(request: Request) -> None:
    settings = request.app.state.waf.settings
    expected = settings.admin_token
    if not expected:
        # Should not happen: the app generates one at startup when none is set.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="control plane is not configured",
        )

    presented = _presented(request)
    # compare_digest rather than == so a wrong token cannot be discovered one
    # character at a time by timing the response.
    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="control plane requires a token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_metrics_access(request: Request) -> None:
    if request.app.state.waf.settings.metrics_public:
        return
    require_admin(request)


ADMIN = [Depends(require_admin)]
METRICS = [Depends(require_metrics_access)]
