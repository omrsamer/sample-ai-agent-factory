// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import type { Origin } from '../../api/client';

/** Tabs of the agent detail page. One list, so the page and its test cannot drift. */
export interface AgentTab {
  id: string;
  label: string;
  /** Shown only for agents the factory deployed, not for records registered by hand. */
  deployedOnly?: boolean;
}

export const ALL_TABS: AgentTab[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'tool-subscriptions', label: 'Tool subscriptions' },
  { id: 'deployment', label: 'Deployment', deployedOnly: true },
  { id: 'traces', label: 'Traces' },
  { id: 'cost', label: 'Cost' },
  { id: 'evaluations', label: 'Release evidence' },
];

export function visibleTabs(origin: Origin): AgentTab[] {
  return ALL_TABS.filter((t) => !t.deployedOnly || origin === 'Deployed');
}

/** The tab to show for a requested id, falling back to the first visible one. */
export function resolveTab(tabs: AgentTab[], requested: string | null | undefined): AgentTab {
  return tabs.find((t) => t.id === requested) ?? tabs[0];
}
