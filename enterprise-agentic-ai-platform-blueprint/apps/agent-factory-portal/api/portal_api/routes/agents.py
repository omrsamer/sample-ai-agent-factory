# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Agents and their per-agent read views."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from portal_api.deps import CurrentPrincipal, EntityId, Service
from portal_api.models.wire import (
    Agent,
    AgentMcpGrant,
    AgentMetrics,
    Deployment,
    EvalRuns,
    RuntimeStatus,
    TracePage,
)

router = APIRouter(prefix="/agents", tags=["agents"])

_FILTER = r"^[A-Za-z0-9 _.:-]{1,128}$"


@router.get("", response_model=list[Agent])
def list_agents(
    _: CurrentPrincipal,
    service: Service,
    lifecycle_state: Annotated[str | None, Query(pattern=_FILTER)] = None,
    business_unit: Annotated[str | None, Query(pattern=_FILTER)] = None,
    region: Annotated[str | None, Query(pattern=_FILTER)] = None,
    platform: Annotated[str | None, Query(pattern=_FILTER)] = None,
    tenant_id: Annotated[str | None, Query(pattern=_FILTER)] = None,
) -> list[Agent]:
    agents = [entry.agent for entry in service.agents()]
    wanted = {
        "lifecycle_state": lifecycle_state,
        "business_unit": business_unit,
        "region": region,
        "platform": platform,
        "tenant_id": tenant_id,
    }
    for name, value in wanted.items():
        if value is not None:
            agents = [a for a in agents if getattr(a, name) == value]
    return agents


@router.get("/{agent_id}", response_model=Agent)
def get_agent(agent_id: EntityId, _: CurrentPrincipal, service: Service) -> Agent:
    return service.agent(agent_id).agent


Stage = Annotated[str | None, Query(pattern=r"^[A-Za-z0-9_-]{1,64}$")]


@router.get("/{agent_id}/runtime", response_model=RuntimeStatus)
def runtime(agent_id: EntityId, _: CurrentPrincipal, service: Service, stage: Stage = None) -> RuntimeStatus:
    return service.runtime_status(agent_id, stage)


@router.get("/{agent_id}/deployments", response_model=list[Deployment])
def deployments(
    agent_id: EntityId,
    _: CurrentPrincipal,
    service: Service,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    stage: Stage = None,
) -> list[Deployment]:
    return service.deployments(agent_id, limit, stage)


@router.get("/{agent_id}/traces", response_model=TracePage)
def traces(
    agent_id: EntityId,
    _: CurrentPrincipal,
    service: Service,
    page: Annotated[int, Query(ge=1, le=100)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    hours: Annotated[int, Query(ge=1, le=720)] = 168,
) -> TracePage:
    return service.traces(agent_id, page, limit, hours)


@router.get("/{agent_id}/metrics", response_model=AgentMetrics)
def metrics(
    agent_id: EntityId,
    _: CurrentPrincipal,
    service: Service,
    date_from: Annotated[str | None, Query(max_length=40)] = None,
    date_to: Annotated[str | None, Query(max_length=40)] = None,
) -> AgentMetrics:
    return service.agent_metrics(agent_id, date_from, date_to)


@router.get("/{agent_id}/evals/runs", response_model=EvalRuns)
def eval_runs(agent_id: EntityId, _: CurrentPrincipal, service: Service) -> EvalRuns:
    return service.eval_runs(agent_id)


@router.get("/{agent_id}/mcp-grants", response_model=list[AgentMcpGrant])
def mcp_grants(agent_id: EntityId, _: CurrentPrincipal, service: Service) -> list[AgentMcpGrant]:
    return service.agent_mcp_grants(agent_id)
