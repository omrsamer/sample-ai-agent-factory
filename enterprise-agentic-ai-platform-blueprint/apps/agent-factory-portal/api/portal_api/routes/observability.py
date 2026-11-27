# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Fleet observability, backed by Amazon CloudWatch."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from portal_api.deps import CurrentPrincipal, Service
from portal_api.identity.provider import console_role
from portal_api.models.wire import ObservabilitySettings, ScopeMetrics
from portal_api.service import Forbidden

router = APIRouter(prefix="/observability", tags=["observability"])


@router.get("/settings", response_model=ObservabilitySettings)
def settings(_: CurrentPrincipal) -> ObservabilitySettings:
    return ObservabilitySettings()


@router.get("/metrics", response_model=ScopeMetrics)
def metrics(
    principal: CurrentPrincipal,
    service: Service,
    scope: Annotated[str, Query(pattern="^(platform|tenant|project)$")] = "platform",
    date_from: Annotated[str | None, Query(max_length=40)] = None,
    date_to: Annotated[str | None, Query(max_length=40)] = None,
) -> ScopeMetrics:
    # The default profile has no per-tenant membership, so every scope answers with the fleet the
    # portal is configured to read. The platform scope is still reserved for the platform role.
    if scope == "platform" and console_role(principal.role)[1] < 2:
        raise Forbidden("The platform scope requires the platform role")
    return service.scope_metrics(date_from, date_to)
