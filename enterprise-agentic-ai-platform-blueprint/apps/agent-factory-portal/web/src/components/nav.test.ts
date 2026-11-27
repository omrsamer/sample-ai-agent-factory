// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, expect, it } from 'vitest';
import appSrc from '../App.tsx?raw';
import { PORTAL_NAV, isNavItemActive, navRoutes, portalNav } from './nav';

describe('PORTAL_NAV', () => {
  it('groups the screens by plane, in order', () => {
    expect(PORTAL_NAV.map((s) => s.label)).toEqual(['Assurance and operations', 'Platform control', 'Resources']);
    expect(PORTAL_NAV[0].items.map((i) => i.label)).toEqual([
      'Fleet',
      'Agents',
      'Tool gateways',
      'Access graph',
      'Observability',
      'Release evidence',
    ]);
    expect(PORTAL_NAV[1].items.map((i) => i.label)).toEqual(['Governance catalog']);
    expect(PORTAL_NAV[2].items.map((i) => i.label)).toEqual(['Documentation']);
  });

  it('has unique destinations, each with a route in the application', () => {
    const routes = navRoutes();
    expect(new Set(routes).size).toBe(routes.length);
    for (const to of routes) {
      expect(appSrc).toContain(`path="${to}"`);
    }
  });

  it('offers nothing from the screens that were removed', () => {
    const routes = navRoutes().join(' ');
    expect(routes).not.toMatch(/ops|marketplace|admin|studio|new/);
    expect(appSrc).not.toMatch(/path="[^"]*\/(new|create|admin|ops)\b/);
  });
});

describe('portalNav', () => {
  it('is exactly the read-only navigation when governed actions are off', () => {
    expect(portalNav({ governedActions: false, approver: true })).toBe(PORTAL_NAV);
    expect(navRoutes(portalNav({ governedActions: false, approver: true }))).not.toEqual(
      expect.arrayContaining(['/registrations', '/approvals']),
    );
  });

  it('adds Registrations under Platform control when they are on, and Approvals for approvers only', () => {
    const labels = (approver: boolean) =>
      portalNav({ governedActions: true, approver }).find((s) => s.id === 'platform-control')!.items.map((i) => i.label);
    expect(labels(false)).toEqual(['Governance catalog', 'Registrations']);
    expect(labels(true)).toEqual(['Governance catalog', 'Registrations', 'Approvals']);
  });
});

describe('isNavItemActive', () => {
  const fleet = PORTAL_NAV[0].items[0];
  const agents = PORTAL_NAV[0].items[1];

  it('matches the home item exactly', () => {
    expect(isNavItemActive(fleet, '/')).toBe(true);
    expect(isNavItemActive(fleet, '/agents')).toBe(false);
  });

  it('matches a section and its children, but not a sibling with the same prefix', () => {
    expect(isNavItemActive(agents, '/agents')).toBe(true);
    expect(isNavItemActive(agents, '/agents/a-1')).toBe(true);
    expect(isNavItemActive(agents, '/agents-archive')).toBe(false);
  });
});
