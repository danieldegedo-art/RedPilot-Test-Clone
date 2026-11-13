"""FastAPI application entrypoint.

Run directly with: uvicorn app.main:app --host 127.0.0.1 --port 8420
(the Docker image's CMD does exactly this -- see Dockerfile).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging
from app.core.control_port import get_control_adapter
from app.db.session import init_db

configure_logging(settings.log_level)
logger = logging.getLogger("qa.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing database schema...")
    await init_db()
    logger.info("Payment QA Framework backend ready on %s:%s", settings.host, settings.port)
    yield
    logger.info("Shutting down Payment QA Framework backend.")


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)

# Local desktop tool talking to a local backend on the same machine. CORS
# itself stays permissive for allowed callers (no cookies/credentials used),
# but the local-only guard middleware runs FIRST (outermost -- see Starlette's
# last-added-runs-first ordering) and rejects anything that is not the
# packaged dashboard or a local dev server BEFORE it reaches CORS or any
# route: a foreign Host header (DNS rebinding) or a non-local Origin
# (cross-site request) never gets a response with permissive CORS headers
# attached in the first place. See enterprise_controls/http_perimeter.py's
# module docstring for the null-origin trade-off and how QA_API_TOKEN closes it.
# Config is derived from Settings (core/config.py) so it is env-overridable like
# everything else. The middleware belongs to the Enterprise Controls and is
# installed through the Control Adapter (it must be added BEFORE CORS to stay the
# outermost layer); if that component is unavailable the adapter logs a CRITICAL
# message and the app starts without it (fail-open availability mode).
get_control_adapter().install_http_perimeter(
    app,
    allowed_hostnames=[h.strip() for h in settings.allowed_hostnames.split(",") if h.strip()],
    extra_allowed_origins=[o.strip() for o in settings.extra_allowed_origins.split(",") if o.strip()],
    allow_null_origin=not settings.strict_local_origins,
    api_token=settings.api_token,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error. Check backend logs for details."})


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}
