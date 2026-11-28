# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Who the caller is: one function, for the read API and for the action functions alike.

The caller is taken from the bearer token, which the function verifies
itself (``portal_api/identity/verify.py``). Nothing of the invocation event
says who the caller is: not the claims Amazon API Gateway puts into the
event after its own check, and nothing else. A principal that can invoke a
function directly writes the whole event, so claims in it would let that
principal name any role: on the read API the role decides who is shown an
incident record.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from fastapi import Depends, Request

from portal_api.config import Settings, dev_auth_enabled, get_settings
from portal_api.identity import verify as tokens
from portal_api.identity.provider import NotAuthenticated, Principal, get_provider, parse_multi_value

logger = logging.getLogger(__name__)

DEV_USER_HEADER = "x-portal-dev-user"
DEV_GROUPS_HEADER = "x-portal-dev-groups"
KEYS_UNAVAILABLE = (
    "The caller could not be verified because the identity provider's signing keys are not available. "
    "Nothing was done. Try again shortly."
)


def dev_claims(request: Request, settings: Any) -> Mapping[str, Any] | None:
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


def bearer_token(request: Request) -> str | None:
    """The token of ``Authorization: Bearer <token>``, or ``None`` when the header is not of that form."""
    scheme, _, value = (request.headers.get("authorization") or "").strip().partition(" ")
    value = value.strip()
    return value if scheme.lower() == "bearer" and value and " " not in value else None


def current_principal(request: Request, settings: Settings = Depends(get_settings)) -> Principal:
    return principal_from_request(request, settings)


def principal_from_request(request: Request, settings: Any) -> Principal:
    """The caller, from the bearer token this function verifies itself.

    ``settings`` needs ``identity_provider``, ``group_role_map`` and
    ``token``: the read API's settings and an action function's both have
    them. Nothing of the event's authorizer context is read. In local
    development (never inside AWS Lambda) the header-based identity is
    accepted instead.
    """
    provider = get_provider(settings.identity_provider)
    if dev_auth_enabled():
        claims = dev_claims(request, settings)
        if claims is not None:
            return provider.principal(claims, settings.group_role_map)
    token = bearer_token(request)
    if token is None or settings.token is None:
        raise NotAuthenticated("no bearer token on the request")
    try:
        claims = tokens.verify(token, settings.token, tokens.keys_for(settings.token.jwks_url))
    except tokens.TokenRejected as exc:
        logger.warning("Bearer token not accepted: %s", exc)
        raise NotAuthenticated("the bearer token was not accepted") from exc
    return provider.principal(claims, settings.group_role_map)
