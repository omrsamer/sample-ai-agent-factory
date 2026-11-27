# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Governance graph and the derived agent-to-gateway grants.

The default profile has no per-end-user grants (the Tool Gateway authorizes
with AWS IAM), so the graph has no ``user`` nodes: an owner group has access
to its agents, and an agent can call the gateways it is linked to.
"""

from __future__ import annotations

from portal_api.mappers.agents import TAG_AGENT, TAG_ENVIRONMENT, TAG_TENANT, AgentEntry, GatewayLink
from portal_api.mappers.mcp import GatewayEntry
from portal_api.models.wire import (
    AgentMcpGrant,
    GovernanceGraph,
    Grant,
    GraphEdge,
    GraphNode,
    PrincipalDetail,
)

_IDENTITY_TAGS = (TAG_TENANT, TAG_AGENT, TAG_ENVIRONMENT)


def derive_links(entry: AgentEntry, gateways: list[GatewayEntry]) -> list[GatewayLink]:
    """Links for an agent that has no registry record, from its runtime.

    In order: the Tool Gateway URL the runtime was configured with; otherwise
    gateways in the same account and Region whose tenant, agent and environment
    tags all equal the runtime's. Nothing derivable means no links.
    """
    runtime = entry.runtime
    if runtime is None:
        return []
    same_scope = [g for g in gateways if g.cell.scope == runtime.cell.scope]
    if runtime.gateway_url:
        wanted = runtime.gateway_url.rstrip("/")
        by_url = [g for g in same_scope if g.url and g.url.rstrip("/") == wanted]
        if by_url:
            return [GatewayLink(g.server.id, g.arn, "runtime_env") for g in by_url]
    identity = tuple(runtime.tags.get(tag) for tag in _IDENTITY_TAGS)
    if not all(identity):
        return []
    return [
        GatewayLink(g.server.id, g.arn, "tags")
        for g in same_scope
        if tuple(g.tags.get(tag) for tag in _IDENTITY_TAGS) == identity
    ]


def assignment_id(agent_id: str, gateway_id: str) -> str:
    return f"derived:{agent_id}:{gateway_id}"


def agent_mcp_grants(entry: AgentEntry, gateways: dict[str, GatewayEntry]) -> list[AgentMcpGrant]:
    grants = []
    for link in entry.links:
        gateway = gateways.get(link.gateway_id)
        grants.append(
            AgentMcpGrant(
                mcp_id=link.gateway_id,
                mcp_name=gateway.server.name if gateway else link.gateway_id,
                assignment_id=assignment_id(entry.agent.id, link.gateway_id),
                source=link.source,
                tool_ids=list(link.tool_ids),
            )
        )
    return grants


def mcp_grants(gateway_id: str, agents: list[AgentEntry]) -> list[Grant]:
    grants = []
    for entry in agents:
        for link in entry.links:
            if link.gateway_id == gateway_id:
                grants.append(
                    Grant(
                        assignment_id=assignment_id(entry.agent.id, gateway_id),
                        principal_id=entry.agent.id,
                        principal_display=entry.agent.name,
                        source=link.source,
                        tool_ids=list(link.tool_ids),
                    )
                )
    return grants


def build_graph(agents: list[AgentEntry], gateways: list[GatewayEntry]) -> GovernanceGraph:
    nodes: dict[str, GraphNode] = {}
    edges: dict[str, GraphEdge] = {}
    by_id = {g.server.id: g for g in gateways}

    for gateway in gateways:
        server = gateway.server
        nodes[f"mcp:{server.id}"] = GraphNode(
            type="mcp",
            id=f"mcp:{server.id}",
            label=server.name,
            ref_id=server.id,
            metadata={
                "kind": server.kind,
                "tenant_id": server.tenant_id,
                "environment": server.environment,
                "enforcement_mode": gateway.enforcement_mode,
                "tool_count": len(server.available_tools),
            },
        )

    for entry in agents:
        agent = entry.agent
        agent_node = f"agent:{agent.id}"
        nodes[agent_node] = GraphNode(
            type="agent",
            id=agent_node,
            label=agent.name,
            ref_id=agent.id,
            metadata={
                "lifecycle_state": agent.lifecycle_state,
                "registration": agent.registration,
                "tenant_id": agent.tenant_id,
                "environment": agent.environment,
            },
        )
        if entry.owner_group:
            group_node = f"group:{entry.owner_group}"
            if group_node not in nodes:
                nodes[group_node] = GraphNode(
                    type="group",
                    id=group_node,
                    label=entry.owner_group,
                    ref_id=entry.owner_group,
                    metadata={"kind": "owner_group"},
                )
            edge_id = f"access:{entry.owner_group}:{agent.id}"
            edges[edge_id] = GraphEdge(id=edge_id, source=group_node, target=agent_node, type="access", role="owner")
        for link in entry.links:
            mcp_node = f"mcp:{link.gateway_id}"
            gateway = by_id.get(link.gateway_id)
            if mcp_node not in nodes:
                # The record names a gateway that is not in a configured cell.
                nodes[mcp_node] = GraphNode(
                    type="mcp",
                    id=mcp_node,
                    label=link.gateway_id,
                    ref_id=link.gateway_id,
                    metadata={"kind": "gateway", "resolved": False},
                )
            edge_id = f"can_call:{agent.id}:{link.gateway_id}"
            edges[edge_id] = GraphEdge(
                id=edge_id,
                source=agent_node,
                target=mcp_node,
                type="can_call",
                role="Invoker",
                has_policy=bool(gateway and gateway.has_policy),
            )

    return GovernanceGraph(nodes=list(nodes.values()), edges=list(edges.values()))


def owner_group_detail(group: str, agents: list[AgentEntry]) -> PrincipalDetail | None:
    """Detail for an owner-group node; ``None`` when no agent names the group."""
    if not any(entry.owner_group == group for entry in agents):
        return None
    return PrincipalDetail(id=group, display_name=group, kind="group")
