// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import type { McpServerKind } from '../../api/client';

/** Tabs of the tool gateway detail page. */
export interface McpServerTab {
  id: string;
  label: string;
  /** Shown only for gateway-kind records, which are the ones that carry a policy engine. */
  gatewayOnly?: boolean;
}

export const ALL_MCP_TABS: McpServerTab[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'tools', label: 'Tools' },
  { id: 'policies', label: 'Policies', gatewayOnly: true },
  { id: 'connected-agents', label: 'Connected agents' },
];

export function visibleMcpTabs(kind: McpServerKind): McpServerTab[] {
  return ALL_MCP_TABS.filter((t) => !t.gatewayOnly || kind === 'gateway');
}

/** The address callers use: the record's own endpoint, else the gateway URL. */
export function mcpEndpoint(
  mcp: { endpoint_url?: string | null; gateway_url?: string | null },
): { url: string; fromGateway: boolean } | null {
  if (mcp.endpoint_url) return { url: mcp.endpoint_url, fromGateway: false };
  if (mcp.gateway_url) return { url: mcp.gateway_url, fromGateway: true };
  return null;
}
