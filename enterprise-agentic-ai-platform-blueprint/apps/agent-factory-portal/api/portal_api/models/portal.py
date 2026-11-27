# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Response models for the endpoints that are new in the Agent Factory Portal."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

HealthState = Literal["healthy", "needs_attention", "critical", "no_data"]


class CellHealth(BaseModel):
    tenant_id: str
    agent_id: str
    environment: str
    account_alias: str
    region: str
    state: HealthState
    alarms_in_alarm: int = 0
    reachable: bool = True
    alarms_total: int = 0
    # Agent.id of the agent deployed in this cell, when one is known; use it to link to the agent.
    agent_ref: str | None = None
    detail: str | None = None


class FleetTotals(BaseModel):
    cells: int = 0
    healthy: int = 0
    needs_attention: int = 0
    critical: int = 0
    no_data: int = 0
    unreachable: int = 0
    alarms_in_alarm: int = 0


class FleetHealth(BaseModel):
    checked_at: str
    cells: list[CellHealth] = Field(default_factory=list)
    totals: FleetTotals = Field(default_factory=FleetTotals)


class CatalogModel(BaseModel):
    model_id: str
    provider: str
    regions: list[str] = Field(default_factory=list)
    status: str


class CatalogTool(BaseModel):
    tool_id: str
    name: str
    description: str | None = None
    owner: str | None = None
    cost_centre: str | None = None
    status: str
    version: str | None = None
    target_arn: str | None = None
