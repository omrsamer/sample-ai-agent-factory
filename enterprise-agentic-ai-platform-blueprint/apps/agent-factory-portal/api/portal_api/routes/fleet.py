# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Fleet health across Workstream cells."""

from __future__ import annotations

from fastapi import APIRouter

from portal_api.deps import CurrentPrincipal, Service
from portal_api.models.portal import FleetHealth

router = APIRouter(prefix="/fleet", tags=["fleet"])


@router.get("/health", response_model=FleetHealth)
def health(_: CurrentPrincipal, service: Service) -> FleetHealth:
    return service.fleet_health_with_agents()
