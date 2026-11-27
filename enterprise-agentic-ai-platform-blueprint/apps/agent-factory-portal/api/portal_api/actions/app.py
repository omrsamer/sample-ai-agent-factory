# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""FastAPI applications of the two action functions.

Each function serves only its own routes. Anything else, including the other
function's routes and every read route, is answered with 404. A function whose
``PORTAL_ACTION_ROLE`` does not match the handler it runs answers 404 for
everything, so a mis-wired function fails closed.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Annotated, Any

import boto3
from fastapi import APIRouter, Depends, FastAPI, Path, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Receive, Scope, Send

from portal_api.actions.engine import ActionEngine, ActionError
from portal_api.aws.session import BOTO_CONFIG
from portal_api.config import ACTION_ROLES, ActionSettings, ConfigError, get_action_settings
from portal_api.identity.deps import principal_from_request
from portal_api.identity.provider import NotAuthenticated, NotAuthorized, Principal
from portal_api.models.portal import ActionResult, DecisionInput, RegistrationInput

logger = logging.getLogger("portal_api.actions")

API_PREFIX = "/api/v1"
RecordId = Annotated[str, Path(pattern=r"^[A-Za-z0-9]{12}$")]
_NOT_FOUND = {"detail": "Not found"}

_lock = threading.Lock()
_clients: dict[str, Any] = {}


def _client(service: str, region: str) -> Any:
    key = f"{service}:{region}"
    with _lock:
        if key not in _clients:
            _clients[key] = boto3.session.Session().client(service, region_name=region, config=BOTO_CONFIG)
        return _clients[key]


def registry_client(settings: ActionSettings = Depends(get_action_settings)) -> Any:
    return _client("agent-registry-control", settings.registry_region)


def dynamodb_client(settings: ActionSettings = Depends(get_action_settings)) -> Any:
    return _client("dynamodb", settings.registry_region)


def action_principal(request: Request, settings: ActionSettings = Depends(get_action_settings)) -> Principal:
    return principal_from_request(request, settings)


def engine(
    settings: ActionSettings = Depends(get_action_settings),
    principal: Principal = Depends(action_principal),
    registry: Any = Depends(registry_client),
    dynamodb: Any = Depends(dynamodb_client),
) -> ActionEngine:
    return ActionEngine(settings, registry, dynamodb, principal)


Engine = Annotated[ActionEngine, Depends(engine)]


class RoleGuardMiddleware:
    """Answers 404 for everything unless this function is configured for the handler it runs."""

    def __init__(self, app: ASGIApp, role: str) -> None:
        self.app = app
        self.role = role

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] != "OPTIONS":
            configured = os.environ.get("PORTAL_ACTION_ROLE")
            if configured != self.role:
                logger.error("Refusing request: handler is %s but PORTAL_ACTION_ROLE is %s", self.role, configured)
                await JSONResponse(_NOT_FOUND, status_code=404)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def _registrar_router() -> APIRouter:
    from portal_api.actions import registrar_flow

    router = APIRouter(prefix="/registrations", tags=["registrations"])

    @router.post("", response_model=ActionResult, status_code=201)
    def create(body: RegistrationInput, engine: Engine) -> ActionResult:
        return registrar_flow.create(engine, body)

    @router.put("/{record_id}", response_model=ActionResult)
    def update(record_id: RecordId, body: RegistrationInput, engine: Engine) -> ActionResult:
        return registrar_flow.update(engine, record_id, body)

    @router.post("/{record_id}/submit", response_model=ActionResult)
    def submit(record_id: RecordId, engine: Engine) -> ActionResult:
        return registrar_flow.submit(engine, record_id)

    @router.delete("/{record_id}", response_model=ActionResult)
    def delete(record_id: RecordId, engine: Engine) -> ActionResult:
        return registrar_flow.delete(engine, record_id)

    return router


def _approver_router() -> APIRouter:
    from portal_api.actions import approver_flow

    router = APIRouter(prefix="/registrations", tags=["registrations"])

    @router.post("/{record_id}/approve", response_model=ActionResult)
    def approve(record_id: RecordId, body: DecisionInput, engine: Engine) -> ActionResult:
        return approver_flow.decide(engine, "approve", record_id, body)

    @router.post("/{record_id}/reject", response_model=ActionResult)
    def reject(record_id: RecordId, body: DecisionInput, engine: Engine) -> ActionResult:
        return approver_flow.decide(engine, "reject", record_id, body)

    return router


def _allowed_origins() -> list[str]:
    try:
        origins = json.loads(os.environ.get("PORTAL_ALLOWED_ORIGINS") or "[]")
    except ValueError:
        return []
    return [o for o in origins if isinstance(o, str) and o != "*"] if isinstance(origins, list) else []


def create_action_app(role: str) -> FastAPI:
    if role not in ACTION_ROLES:
        raise ValueError("role must be registrar or approver")
    logging.getLogger().setLevel(os.environ.get("PORTAL_LOG_LEVEL", "INFO"))
    app = FastAPI(
        title=f"Agent Factory Portal {role} API", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.add_middleware(RoleGuardMiddleware, role=role)
    origins = _allowed_origins()
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["POST", "PUT", "DELETE"] if role == "registrar" else ["POST"],
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

    @app.exception_handler(ActionError)
    async def action_error(_: Request, exc: ActionError) -> JSONResponse:
        return JSONResponse({"detail": exc.detail, **exc.extra}, status_code=exc.status)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        # A route this function does not serve (wrong path or wrong method) does not exist here.
        if exc.status_code in (404, 405):
            return JSONResponse(_NOT_FOUND, status_code=404)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        detail = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()
        ]
        return JSONResponse({"detail": detail}, status_code=422)

    app.include_router(_registrar_router() if role == "registrar" else _approver_router(), prefix=API_PREFIX)
    return app
