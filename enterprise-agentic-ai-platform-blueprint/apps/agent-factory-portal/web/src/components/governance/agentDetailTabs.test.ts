// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, expect, it } from 'vitest';
import pageSrc from './AgentDetail.tsx?raw';
import { ALL_TABS, resolveTab, visibleTabs } from './agentDetailTabs';

describe('agent detail tabs', () => {
  it('lists the read-only tabs in order when governed actions are off', () => {
    expect(visibleTabs('Deployed').map((t) => t.id)).toEqual(['overview', 'tool-subscriptions', 'deployment', 'traces', 'cost', 'evaluations']);
    expect(visibleTabs('Deployed', { governedActions: false }).map((t) => t.id)).not.toContain('containment');
    expect(ALL_TABS.find((t) => t.id === 'evaluations')?.label).toBe('Release evidence');
  });

  it('adds Containment only when governed actions are on', () => {
    expect(visibleTabs('Deployed', { governedActions: true }).map((t) => t.id)).toEqual([
      'overview', 'tool-subscriptions', 'deployment', 'traces', 'cost', 'evaluations', 'containment',
    ]);
    expect(visibleTabs('Registered', { governedActions: true }).map((t) => t.id)).toContain('containment');
  });

  it('has no access-grant or test-invoke surface', () => {
    expect(ALL_TABS.map((t) => t.id)).not.toEqual(expect.arrayContaining(['access', 'mcp-servers']));
    expect(pageSrc).not.toMatch(/InvokePanel|AccessTab/);
  });

  it('shows Deployment only for agents the factory deployed', () => {
    expect(visibleTabs('Deployed').map((t) => t.id)).toContain('deployment');
    expect(visibleTabs('Registered').map((t) => t.id)).not.toContain('deployment');
  });

  it('renders a branch for every tab id', () => {
    for (const tab of ALL_TABS.filter((t) => t.id !== 'evaluations')) {
      expect(pageSrc).toContain(`activeTab.id === '${tab.id}'`);
    }
    expect(pageSrc).toContain('<EvaluationsTab');
  });
});

describe('resolveTab', () => {
  const tabs = visibleTabs('Registered');
  it('returns the requested tab when it is visible', () => {
    expect(resolveTab(tabs, 'cost').id).toBe('cost');
  });
  it('falls back to the first tab for an unknown, hidden or absent id', () => {
    expect(resolveTab(tabs, 'deployment').id).toBe('overview');
    expect(resolveTab(tabs, 'containment').id).toBe('overview');
    expect(resolveTab(tabs, 'nope').id).toBe('overview');
    expect(resolveTab(tabs, null).id).toBe('overview');
  });
});
