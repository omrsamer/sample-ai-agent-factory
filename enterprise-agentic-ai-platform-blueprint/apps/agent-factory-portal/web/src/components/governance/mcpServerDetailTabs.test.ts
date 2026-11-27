// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, expect, it } from 'vitest';
import { ALL_MCP_TABS, mcpEndpoint, visibleMcpTabs } from './mcpServerDetailTabs';

describe('tool gateway tabs', () => {
  it('lists Overview, Tools, Policies and Connected agents', () => {
    expect(ALL_MCP_TABS.map((t) => t.label)).toEqual(['Overview', 'Tools', 'Policies', 'Connected agents']);
  });

  it('shows Policies only for gateway-kind records', () => {
    expect(visibleMcpTabs('gateway').map((t) => t.id)).toContain('policies');
    expect(visibleMcpTabs('standard').map((t) => t.id)).not.toContain('policies');
    expect(visibleMcpTabs('runtime').map((t) => t.id)).not.toContain('policies');
  });
});

describe('mcpEndpoint', () => {
  it('prefers the record endpoint, then the gateway URL', () => {
    expect(mcpEndpoint({ endpoint_url: 'https://tools.example.com/mcp', gateway_url: 'https://gw.example.com/mcp' })).toEqual({
      url: 'https://tools.example.com/mcp',
      fromGateway: false,
    });
    expect(mcpEndpoint({ endpoint_url: null, gateway_url: 'https://gw.example.com/mcp' })).toEqual({
      url: 'https://gw.example.com/mcp',
      fromGateway: true,
    });
    expect(mcpEndpoint({})).toBeNull();
  });
});
