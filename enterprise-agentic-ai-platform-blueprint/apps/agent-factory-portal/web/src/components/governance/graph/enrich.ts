// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { Agent, GovernanceGraph, UserTenant } from '../../../api/client';
import { agentContext, isContained } from '../inventory';
import { resolveTenantName } from '../tenantUi';

/**
 * The access graph with what the inventory knows about each agent added to its node: whether
 * it is contained, and the tenant and account that tell two agents of one name apart. The graph
 * API carries neither, so they are joined from the agents list by the agent's id. A node whose
 * agent is not in the list is left as it came.
 */
export function enrichGraph(
  graph: GovernanceGraph,
  agents: readonly Agent[] | null | undefined,
  tenants?: UserTenant[] | null,
): GovernanceGraph {
  if (!agents || agents.length === 0) return graph;
  const byId = new Map(agents.map((agent) => [agent.id, agent]));
  return {
    ...graph,
    nodes: graph.nodes.map((node) => {
      const agent = node.type === 'agent' ? byId.get(node.ref_id) : undefined;
      if (!agent) return node;
      return {
        ...node,
        metadata: {
          ...node.metadata,
          contained: node.metadata.contained === true || isContained(agent),
          context: agentContext(agent, resolveTenantName(agent.tenant_id, tenants)),
        },
      };
    }),
  };
}

/** The tenant and account of an agent node, as joined by `enrichGraph`, or an empty string. */
export function nodeContext(metadata: Record<string, unknown>): string {
  return typeof metadata.context === 'string' ? metadata.context : '';
}
