# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Governance graph and principal detail."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from portal_api.deps import CurrentPrincipal, PrincipalId, Service
from portal_api.models.wire import GovernanceGraph, PrincipalDetail
from portal_api.service import NotFound

router = APIRouter(tags=["governance"])


@router.get("/governance-graph", response_model=GovernanceGraph)
def graph(_: CurrentPrincipal, service: Service) -> GovernanceGraph:
    return service.graph()


# The console front end reads the principal under the graph; both paths are served.
@router.get("/principals/{principal_id}", response_model=PrincipalDetail)
@router.get("/governance-graph/principals/{principal_id}", response_model=PrincipalDetail)
def principal(
    principal_id: PrincipalId,
    _: CurrentPrincipal,
    service: Service,
    kind: Annotated[str, Query(pattern="^(user|group)$")] = "group",
) -> PrincipalDetail:
    if kind != "group":
        # The default profile has no per-end-user grants, so there are no user principals.
        raise NotFound("Principal not found")
    return service.principal(principal_id)
