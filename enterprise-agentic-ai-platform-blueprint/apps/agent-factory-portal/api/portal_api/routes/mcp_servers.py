# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""MCP servers: one per Tool Gateway a cell reader read or the organization registry detected."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from portal_api.deps import CurrentPrincipal, EntityId, Service
from portal_api.models.wire import CedarPolicySet, Grant, McpServer, PolicyEnforcement

router = APIRouter(prefix="/mcp-servers", tags=["mcp-servers"])

_FILTER = r"^[A-Za-z0-9 _.:-]{1,128}$"


@router.get("", response_model=list[McpServer])
def list_servers(
    _: CurrentPrincipal,
    service: Service,
    lifecycle_state: Annotated[str | None, Query(pattern=_FILTER)] = None,
    kind: Annotated[str | None, Query(pattern=_FILTER)] = None,
    region: Annotated[str | None, Query(pattern=_FILTER)] = None,
    tenant_id: Annotated[str | None, Query(pattern=_FILTER)] = None,
) -> list[McpServer]:
    servers = [entry.server for entry in service.gateways()]
    wanted = {"lifecycle_state": lifecycle_state, "kind": kind, "region": region, "tenant_id": tenant_id}
    for name, value in wanted.items():
        if value is not None:
            servers = [s for s in servers if getattr(s, name) == value]
    return servers


@router.get("/{server_id}", response_model=McpServer)
def get_server(server_id: EntityId, _: CurrentPrincipal, service: Service) -> McpServer:
    return service.gateway(server_id).server


@router.get("/{server_id}/policies", response_model=CedarPolicySet)
def policies(server_id: EntityId, _: CurrentPrincipal, service: Service) -> CedarPolicySet:
    return service.policies(server_id)


@router.get("/{server_id}/policy-enforcement", response_model=PolicyEnforcement)
def policy_enforcement(server_id: EntityId, _: CurrentPrincipal, service: Service) -> PolicyEnforcement:
    server = service.gateway(server_id).server
    return PolicyEnforcement(
        enforcement_mode=server.cedar_enforcement_mode, engine_id=server.cedar_policy_engine_id, detail=server.detail
    )


@router.get("/{server_id}/grants", response_model=list[Grant])
def grants(server_id: EntityId, _: CurrentPrincipal, service: Service) -> list[Grant]:
    return service.mcp_grants(server_id)
