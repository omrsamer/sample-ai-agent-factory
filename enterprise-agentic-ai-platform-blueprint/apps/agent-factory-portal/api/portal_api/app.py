# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""FastAPI application for the Agent Factory Portal API (read-only)."""

from __future__ import annotations

import json
import logging
import os

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from portal_api.aws.logs import UnsafeQueryValue
from portal_api.aws.session import error_code
from portal_api.config import ConfigError
from portal_api.identity.provider import NotAuthenticated, NotAuthorized
from portal_api.routes import agents, catalog, fleet, governance, guardrails, mcp_servers, observability, users
from portal_api.service import BadRequest, Forbidden, NotFound

logger = logging.getLogger("portal_api")

API_PREFIX = "/api/v1"


class ReadOnlyMiddleware:
    """Answers every request that is not a GET with 405. There is no mutating code path."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] != "GET":
            response = JSONResponse(
                {"detail": "Method not allowed. The Agent Factory Portal API is read-only."},
                status_code=405,
                headers={"Allow": "GET"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _allowed_origins() -> list[str]:
    """Origins for CORS. Malformed input means no origins; request-time validation reports it."""
    try:
        origins = json.loads(os.environ.get("PORTAL_ALLOWED_ORIGINS") or "[]")
    except ValueError:
        return []
    if not isinstance(origins, list):
        return []
    return [o for o in origins if isinstance(o, str) and o != "*"]


def create_app() -> FastAPI:
    logging.getLogger().setLevel(os.environ.get("PORTAL_LOG_LEVEL", "INFO"))
    app = FastAPI(
        title="Agent Factory Portal API",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Added first so it sits inside CORS: a CORS preflight is answered by the CORS layer,
    # and every other non-GET request is refused here before any route or dependency runs.
    app.add_middleware(ReadOnlyMiddleware)
    origins = _allowed_origins()
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET"],
            allow_headers=["authorization", "content-type"],
            max_age=600,
        )

    @app.exception_handler(ConfigError)
    async def config_error(_: Request, exc: ConfigError) -> JSONResponse:
        logger.error("Refusing request, configuration is invalid: %s", exc)
        return JSONResponse({"detail": f"Portal configuration error: {exc}"}, status_code=500)

    @app.exception_handler(NotAuthenticated)
    async def not_authenticated(_: Request, exc: NotAuthenticated) -> JSONResponse:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    @app.exception_handler(NotAuthorized)
    async def not_authorized(_: Request, exc: NotAuthorized) -> JSONResponse:
        return JSONResponse({"detail": "No portal role is assigned to this identity"}, status_code=403)

    @app.exception_handler(Forbidden)
    async def forbidden(_: Request, exc: Forbidden) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.exception_handler(NotFound)
    async def not_found(_: Request, exc: NotFound) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(BadRequest)
    async def bad_request(_: Request, exc: BadRequest) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(UnsafeQueryValue)
    async def unsafe_query(_: Request, exc: UnsafeQueryValue) -> JSONResponse:
        logger.error("Refused to build a query: %s", exc)
        return JSONResponse({"detail": "The request could not be turned into a safe query"}, status_code=400)

    async def aws_error(_: Request, exc: Exception) -> JSONResponse:
        code = error_code(exc)
        logger.error("AWS call failed: %s", code)
        return JSONResponse({"detail": f"An AWS service call failed ({code})"}, status_code=502)

    app.add_exception_handler(ClientError, aws_error)
    app.add_exception_handler(BotoCoreError, aws_error)

    health = APIRouter()

    @health.get("/health")
    def liveness() -> dict[str, str]:
        """Unauthenticated liveness probe. Returns no data and touches no configuration."""
        return {"status": "ok"}

    app.include_router(health, prefix=API_PREFIX)
    for module in (users, agents, mcp_servers, governance, observability, guardrails, fleet, catalog):
        app.include_router(module.router, prefix=API_PREFIX)
    return app
