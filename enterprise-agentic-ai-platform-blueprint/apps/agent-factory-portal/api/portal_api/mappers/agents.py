# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Agents: registry records merged with runtimes discovered in cell accounts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from portal_api.config import Cell
from portal_api.mappers import registry as registry_mapper
from portal_api.mappers.common import EPOCH_ISO, arn_parts, arn_resource_id, iso, now_iso, text
from portal_api.models.wire import Agent, Deployment, RuntimeStatus

_CLASSIFICATION = {
    "public": "Public",
    "internal": "Internal",
    "confidential": "Confidential",
    "restricted": "Restricted",
}

# Native runtime status -> the console's runtime status vocabulary.
RUNTIME_STATUS = {
    "READY": "ready",
    "CREATING": "creating",
    "UPDATING": "updating",
    "CREATE_FAILED": "failed",
    "UPDATE_FAILED": "failed",
    "DELETING": "unknown",
}

TAG_TENANT = "tenant-id"
TAG_AGENT = "agent-id"
TAG_APPLICATION = "application-id"
TAG_ENVIRONMENT = "environment"
TAG_COST_CENTRE = "cost-centre"


@dataclass(frozen=True)
class Runtime:
    """A runtime discovered in a cell account, normalised."""

    arn: str
    runtime_id: str
    name: str
    status: str
    version: str | None
    description: str | None
    created_at: str | None
    updated_at: str | None
    tags: dict[str, str]
    gateway_url: str | None
    cell: Cell
    account_id: str
    region: str


@dataclass(frozen=True)
class GatewayLink:
    """A derived, read-only edge from an agent to a Tool Gateway."""

    gateway_id: str
    gateway_arn: str | None
    source: str  # "registry" | "runtime_env" | "tags"
    tool_ids: tuple[str, ...] = ()


@dataclass
class AgentEntry:
    agent: Agent
    owner_group: str | None = None
    runtime: Runtime | None = None
    runtime_arn: str | None = None
    # The configured cell whose tenant, agent and environment equal this agent's (pipeline, alarms).
    cell: Cell | None = None
    # A configured cell whose reader role can read this agent's account and Region.
    access_cell: Cell | None = None
    links: list[GatewayLink] = field(default_factory=list)


def runtime_from_bundle(bundle: dict[str, Any], cell: Cell) -> Runtime:
    summary = bundle.get("summary") or {}
    detail = bundle.get("detail") or {}
    arn = summary["agentRuntimeArn"]
    parts = arn_parts(arn) or {}
    return Runtime(
        arn=arn,
        runtime_id=summary.get("agentRuntimeId") or arn_resource_id(arn) or arn,
        name=summary.get("agentRuntimeName") or summary.get("agentRuntimeId") or arn,
        status=str(summary.get("status") or "UNKNOWN"),
        version=text(str(summary.get("agentRuntimeVersion") or "")),
        description=text(summary.get("description")),
        created_at=iso(detail.get("createdAt")),
        updated_at=iso(summary.get("lastUpdatedAt")),
        tags=dict(bundle.get("tags") or {}),
        gateway_url=text(detail.get("gatewayUrl")),
        cell=cell,
        account_id=parts.get("account") or cell.account_id,
        region=parts.get("region") or cell.region,
    )


def registered_agent(
    record: dict[str, Any], runtime: Runtime | None, cell: Cell | None, access_cell: Cell | None = None
) -> AgentEntry:
    governance = registry_mapper.agent_governance(record)
    runtime_arn = governance.runtime_arn
    parts = arn_parts(runtime_arn) or {}
    gateway_id = arn_resource_id(governance.gateway_arn)
    environment = governance.environment
    created = iso(record.get("createdAt")) or EPOCH_ISO
    agent = Agent(
        id=str(record["recordId"]),
        # The agent's own id is its name; the registry record name is kept in record_name.
        name=governance.agent_id
        or text(record.get("displayName"))
        or text(record.get("name"))
        or str(record["recordId"]),
        record_name=text(record.get("name")),
        purpose=governance.business_purpose or text(record.get("description")),
        sponsor_email=governance.contact,
        business_unit=governance.owner_group,
        region=parts.get("region") or (cell.region if cell else None),
        data_classification=_CLASSIFICATION.get((governance.data_classification or "").lower()),
        framework=governance.framework,
        mcp_server_ids=[gateway_id] if gateway_id else [],
        declared_mcp_server_ids=[gateway_id] if gateway_id else [],
        origin="Deployed" if runtime_arn else "Registered",
        lifecycle_state=registry_mapper.lifecycle_state(record),
        agent_arn=runtime_arn,
        agent_arns={environment: runtime_arn} if runtime_arn and environment else None,
        tenant_id=governance.tenant_id,
        created_at=created,
        updated_at=iso(record.get("updatedAt")) or created,
        created_by=text(record.get("createdBy")),
        registration="registered",
        registry_status=text(record.get("status")),
        environment=environment,
        account_id=parts.get("account") or (cell.account_id if cell else None),
        runtime_status=RUNTIME_STATUS.get(runtime.status, "unknown") if runtime else None,
        governance=governance,
    )
    links = (
        [GatewayLink(gateway_id, governance.gateway_arn, "registry", tuple(governance.subscribed_tool_ids))]
        if gateway_id
        else []
    )
    return AgentEntry(
        agent=agent,
        owner_group=governance.owner_group,
        runtime=runtime,
        runtime_arn=runtime_arn,
        cell=cell,
        access_cell=runtime.cell if runtime else access_cell,
        links=links,
    )


def discovered_agent(runtime: Runtime, cell: Cell | None = None) -> AgentEntry:
    """A runtime that no registry record references yet."""
    tags = runtime.tags
    environment = tags.get(TAG_ENVIRONMENT) or runtime.cell.environment
    updated = runtime.updated_at or runtime.created_at or EPOCH_ISO
    agent = Agent(
        id=runtime.runtime_id,
        name=tags.get(TAG_AGENT) or runtime.name,
        purpose=runtime.description,
        business_unit=tags.get(TAG_COST_CENTRE),
        region=runtime.region,
        origin="Deployed",
        lifecycle_state="discovered",
        agent_arn=runtime.arn,
        agent_arns={environment: runtime.arn},
        tenant_id=tags.get(TAG_TENANT),
        created_at=runtime.created_at or updated,
        updated_at=updated,
        registration="discovered",
        environment=environment,
        account_id=runtime.account_id,
        runtime_status=RUNTIME_STATUS.get(runtime.status, "unknown"),
    )
    return AgentEntry(agent=agent, runtime=runtime, runtime_arn=runtime.arn, cell=cell, access_cell=runtime.cell)


def runtime_status(entry: AgentEntry, reachable: bool) -> RuntimeStatus:
    agent = entry.agent
    stage = agent.environment or "unknown"
    if not entry.runtime_arn:
        return RuntimeStatus(agent_id=agent.id, stage=stage, status="not_deployed", checked_at=now_iso())
    if entry.runtime is None:
        detail = (
            "The runtime was not found in its cell account."
            if reachable
            else "The cell account could not be reached, or it is not a configured cell."
        )
        return RuntimeStatus(
            agent_id=agent.id,
            stage=stage,
            status="unknown",
            runtime_arn=entry.runtime_arn,
            checked_at=now_iso(),
            detail=detail,
        )
    runtime = entry.runtime
    return RuntimeStatus(
        agent_id=agent.id,
        stage=stage,
        status=RUNTIME_STATUS.get(runtime.status, "unknown"),
        runtime_arn=runtime.arn,
        image_tag=f"v{runtime.version}" if runtime.version else None,
        checked_at=now_iso(),
        detail=None if runtime.status in RUNTIME_STATUS else f"Runtime status {runtime.status}",
    )


_VERSION_OUTCOME = {"READY": "succeeded", "CREATING": "started", "UPDATING": "started"}


def deployments(entry: AgentEntry, versions: list[dict[str, Any]], limit: int) -> list[Deployment]:
    """Runtime versions as the console's append-only deployment rows, newest first."""
    stage = entry.agent.environment or "unknown"
    rows: list[Deployment] = []
    for version in versions:
        number = str(version.get("agentRuntimeVersion") or "")
        at = iso(version.get("lastUpdatedAt")) or EPOCH_ISO
        status = str(version.get("status") or "")
        outcome = _VERSION_OUTCOME.get(status, "failed" if status.endswith("FAILED") else "started")
        runtime_id = version.get("agentRuntimeId") or (entry.runtime.runtime_id if entry.runtime else entry.agent.id)
        rows.append(
            Deployment(
                id=f"{runtime_id}:v{number}",
                agent_id=entry.agent.id,
                stage=stage,
                seq_key=f"{runtime_id}#{stage}#{at}#v{number}",
                image_tag=f"v{number}",
                outcome=outcome,
                started_at=at,
                completed_at=at if outcome != "started" else None,
            )
        )
    rows.sort(key=lambda r: (r.started_at, r.image_tag), reverse=True)
    return rows[:limit]
