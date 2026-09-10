"""The application: proxy, control plane and console in one process."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from mlwaf.waf import api, proxy
from mlwaf.waf.config import Settings, get_settings
from mlwaf.waf.logging_config import configure
from mlwaf.waf.state import AppState

log = logging.getLogger("mlwaf.app")
CONSOLE_DIR = Path(__file__).parent / "console"


def create_app(settings: Settings | None = None, bundle: dict | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state = AppState(settings, bundle=bundle)
        app.state.waf = state
        await state.startup()
        try:
            yield
        finally:
            # Runs after uvicorn has stopped accepting and drained in flight
            # requests, so nothing is cut off mid response.
            await state.shutdown()
            log.info("waf stopped")

    app = FastAPI(
        title="mlwaf",
        description="ML web application firewall",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/_waf/docs",
        openapi_url="/_waf/openapi.json",
    )

    # Order matters. The control plane and console claim their prefixes first;
    # the proxy's catch all route is registered last so it takes everything else.
    app.include_router(api.router)

    if CONSOLE_DIR.exists():
        app.mount(
            "/_waf/static", StaticFiles(directory=str(CONSOLE_DIR)), name="console-static"
        )

        @app.get("/_waf", include_in_schema=False)
        @app.get("/_waf/", include_in_schema=False)
        async def console() -> FileResponse:
            return FileResponse(CONSOLE_DIR / "index.html")

    app.include_router(proxy.router)
    return app


def main() -> None:
    import uvicorn

    settings = get_settings()
    configure()
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_config=None,
        access_log=False,
        timeout_graceful_shutdown=20,
    )


if __name__ == "__main__":
    main()
