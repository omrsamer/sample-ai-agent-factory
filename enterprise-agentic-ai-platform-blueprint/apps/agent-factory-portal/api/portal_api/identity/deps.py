# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""FastAPI dependencies that resolve the caller."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import Depends, Request

from portal_api.config import Settings, dev_auth_enabled, get_settings
from portal_api.identity.provider import NotAuthenticated, Principal, get_provider, parse_multi_value

DEV_USER_HEADER = "x-portal-dev-user"
DEV_GROUPS_HEADER = "x-portal-dev-groups"


def jwt_claims(request: Request) -> Mapping[str, Any] | None:
    """Claims validated by the API Gateway JWT authorizer, if the request came through it."""
    event = request.scope.get("aws.event")
    if not isinstance(event, dict):
        return None
    try:
        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
    except (KeyError, TypeError):
        return None
    return claims if isinstance(claims, dict) and claims else None


def _dev_claims(request: Request, settings: Settings) -> Mapping[str, Any] | None:
    """Local development only: build claims from request headers.

    The role still comes from PORTAL_GROUP_ROLE_MAP, so a developer exercises the
    same mapping path as production. ``dev_auth_enabled`` is false whenever
    AWS_LAMBDA_FUNCTION_NAME is present, so this can never be reached in Lambda.
    """
    user = request.headers.get(DEV_USER_HEADER)
    if not user:
        return None
    groups = list(parse_multi_value(f"[{request.headers.get(DEV_GROUPS_HEADER, '')}]"))
    if settings.identity_provider == "entra":
        return {"oid": user, "preferred_username": user, "name": user, "groups": groups}
    return {"sub": user, "email": user, "cognito:username": user, "cognito:groups": groups}


def current_principal(request: Request, settings: Settings = Depends(get_settings)) -> Principal:
    claims = jwt_claims(request)
    if claims is None and dev_auth_enabled():
        claims = _dev_claims(request, settings)
    if claims is None:
        raise NotAuthenticated("no validated claims on the request")
    return get_provider(settings.identity_provider).principal(claims, settings.group_role_map)
