from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from gamis.runtime import LocalRuntime

from .api import APIContext, router

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_PATH = REPOSITORY_ROOT / "gamis_dashboard.html"
LOGGER = logging.getLogger(__name__)


def _origins() -> list[str]:
    configured = os.getenv("GAMIS_CORS_ORIGINS")
    if configured is not None:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    return ["http://localhost:8000", "http://127.0.0.1:8000",
            "http://localhost:5173", "http://127.0.0.1:5173"]


def create_app(*, runtime: LocalRuntime | None = None, state_dir: Path | None = None) -> FastAPI:
    supplied_runtime = runtime

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        active_runtime = supplied_runtime
        if active_runtime is None:
            default_state = os.getenv("GAMIS_HOME", str(Path.home() / ".gamis"))
            path = state_dir or Path(os.getenv("GAMIS_STATE_DIR", default_state))
            active_runtime = LocalRuntime(path)
        ctx = APIContext(active_runtime)
        app.state.gamis = ctx
        try:
            yield
        finally:
            ctx.close()

    app = FastAPI(
        title="GAMIS Local API", version="1.0.0",
        description="HTTP adapter for the existing GAMIS runtime. All worker tool execution remains Gateway-mediated.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware, allow_origins=_origins(), allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Content-Type"],
    )
    app.include_router(router)

    @app.exception_handler(HTTPException)
    async def http_error_handler(_request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict):
            code = str(detail.get("code", f"HTTP_{exc.status_code}"))
            message = str(detail.get("message", detail))
        else:
            code, message = f"HTTP_{exc.status_code}", str(detail)
        return JSONResponse(status_code=exc.status_code, content={"error": {"code": code, "message": message}},
                            headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['type']}"
            for error in exc.errors()
        )
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "INVALID_REQUEST",
                               "message": "Request validation failed." if not details else details}},
        )

    @app.exception_handler(Exception)
    async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
        LOGGER.error("Unhandled GAMIS API error for %s: %s", request.url.path, exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "message": "The request could not be completed."}},
        )

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        if not DASHBOARD_PATH.is_file():
            return FileResponse(REPOSITORY_ROOT / "frontend" / "index.html")
        return FileResponse(DASHBOARD_PATH, media_type="text/html")

    @app.get("/api", include_in_schema=False)
    def api_root() -> dict[str, str]:
        return {"service": "GAMIS Local API", "docs": "/docs", "health": "/health"}

    return app
app = create_app()
