// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import type { Agent, GovernanceGraph } from '../../../api/client';
import { enrichGraph, nodeContext } from './enrich';

// The graph API's own shape: lifecycle, registration, tenant and environment, and nothing about containment.
const graph = (): GovernanceGraph => ({
  nodes: [
    { type: 'group', id: 'group:travel', label: 'travel-workstream', ref_id: 'travel', metadata: { kind: 'owner_group' } },
    { type: 'agent', id: 'agent:rec-ws1', label: 'travel-agent', ref_id: 'rec-ws1', metadata: { lifecycle_state: 'approved', registration: 'registered', tenant_id: 'ws1' } },
    { type: 'agent', id: 'agent:rec-ws2', label: 'travel-agent', ref_id: 'rec-ws2', metadata: { lifecycle_state: 'approved', registration: 'registered', tenant_id: 'ws2' } },
    { type: 'mcp', id: 'mcp:gw-1', label: 'tool-gateway', ref_id: 'gw-1', metadata: { kind: 'gateway' } },
  ],
  edges: [{ id: 'e1', source: 'agent:rec-ws1', target: 'mcp:gw-1', type: 'can_call', role: 'Invoker', has_policy: true }],
});

const agent = (over: Partial<Agent>): Agent =>
  ({ id: 'a', name: 'travel-agent', mcp_server_ids: [], origin: 'Deployed', identity_status: 'none', lifecycle_state: 'approved', auth_type: 'none', created_at: '', updated_at: '', ...over }) as Agent;

const AGENTS = [
  agent({ id: 'rec-ws1', tenant_id: 'ws1', account_alias: 'workstream-ws1', flags: { contained: false } }),
  agent({ id: 'rec-ws2', tenant_id: 'ws2', account_alias: 'workstream-ws2', flags: { contained: true } }),
];

describe('enrichGraph', () => {
  it('marks a contained agent, which the graph API does not say', () => {
    const nodes = enrichGraph(graph(), AGENTS).nodes;
    expect(nodes.find((n) => n.ref_id === 'rec-ws2')?.metadata.contained).toBe(true);
    expect(nodes.find((n) => n.ref_id === 'rec-ws1')?.metadata.contained).toBe(false);
  });

  it('tells two agents of one name apart by tenant and account', () => {
    const nodes = enrichGraph(graph(), AGENTS, [{ id: 'ws2', name: 'Workstream two', line_of_business: '', stages: {} }]).nodes;
    expect(nodeContext(nodes.find((n) => n.ref_id === 'rec-ws1')!.metadata)).toBe('ws1 · workstream-ws1');
    expect(nodeContext(nodes.find((n) => n.ref_id === 'rec-ws2')!.metadata)).toBe('Workstream two · workstream-ws2');
  });

  it('keeps what the graph API sent and touches only agent nodes', () => {
    const before = graph();
    const after = enrichGraph(before, AGENTS);
    expect(after.edges).toBe(before.edges);
    expect(after.nodes.find((n) => n.type === 'group')).toBe(before.nodes[0]);
    expect(after.nodes.find((n) => n.type === 'mcp')).toBe(before.nodes[3]);
    expect(after.nodes.find((n) => n.ref_id === 'rec-ws1')?.metadata).toMatchObject({ lifecycle_state: 'approved', registration: 'registered', tenant_id: 'ws1' });
  });

  it('keeps a containment mark the graph API did send', () => {
    const marked = graph();
    marked.nodes[1].metadata.contained = true;
    expect(enrichGraph(marked, AGENTS).nodes[1].metadata.contained).toBe(true);
  });

  it('leaves the graph as it came when the agents could not be read or an agent is not listed', () => {
    const before = graph();
    expect(enrichGraph(before, null)).toBe(before);
    expect(enrichGraph(before, [])).toBe(before);
    expect(enrichGraph(before, [agent({ id: 'someone-else' })]).nodes[1]).toBe(before.nodes[1]);
  });

  it('reads no context from a node that has none', () => {
    expect(nodeContext({})).toBe('');
    expect(nodeContext({ context: 7 })).toBe('');
  });
});
