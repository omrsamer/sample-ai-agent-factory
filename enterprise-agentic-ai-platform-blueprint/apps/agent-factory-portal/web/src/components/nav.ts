// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.

/** Sidebar navigation, grouped by the blueprint's planes. One source for the sidebar and its test. */
export interface NavItem {
  to: string;
  label: string;
  /** SVG path data for a 24x24 outline icon. */
  icon: string;
  /** Match the route exactly instead of by prefix. */
  exact?: boolean;
}

export interface NavSection {
  id: string;
  label: string;
  items: NavItem[];
}

const ICON = {
  fleet: 'M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25',
  agents: 'M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456z',
  tools: 'M11.42 15.17L17.25 21A2.652 2.652 0 0021 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 11-3.586-3.586l6.837-5.63m5.108-.233c.55-.164 1.163-.188 1.743-.14a4.5 4.5 0 004.486-6.336l-3.276 3.277a3.004 3.004 0 01-2.25-2.25l3.276-3.276a4.5 4.5 0 00-6.336 4.486c.091 1.076-.071 2.264-.904 2.95l-.102.085',
  graph: 'M7.217 10.907a2.25 2.25 0 100 2.186m0-2.186c.18.324.283.696.283 1.093s-.103.77-.283 1.093m0-2.186l9.566-5.314m-9.566 7.5l9.566 5.314m0 0a2.25 2.25 0 103.935 2.186 2.25 2.25 0 00-3.935-2.186zm0-12.814a2.25 2.25 0 103.933-2.185 2.25 2.25 0 00-3.933 2.185z',
  eye: 'M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z M15 12a3 3 0 11-6 0 3 3 0 016 0z',
  evidence: 'M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
  catalog: 'M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.75h-.152c-3.196 0-6.1-1.248-8.25-3.285z',
  // Plain outline shapes drawn for the portal.
  registrations: 'M7 3h7l5 5v13H7V3z M14 3v5h5 M10 13h6 M10 17h6',
  approvals: 'M12 3l7 3.5V12c0 4.4-2.9 7.9-7 9-4.1-1.1-7-4.6-7-9V6.5L12 3z M9 12l2 2 4-4',
  docs: 'M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25',
} as const;

export const PORTAL_NAV: NavSection[] = [
  {
    id: 'assurance-operations',
    label: 'Assurance and operations',
    items: [
      { to: '/', label: 'Fleet', icon: ICON.fleet, exact: true },
      { to: '/agents', label: 'Agents', icon: ICON.agents },
      { to: '/tool-gateways', label: 'Tool gateways', icon: ICON.tools },
      { to: '/access-graph', label: 'Access graph', icon: ICON.graph },
      { to: '/observability', label: 'Observability', icon: ICON.eye },
      { to: '/release-evidence', label: 'Release evidence', icon: ICON.evidence },
    ],
  },
  {
    id: 'platform-control',
    label: 'Platform control',
    items: [{ to: '/catalog', label: 'Governance catalog', icon: ICON.catalog }],
  },
  {
    id: 'resources',
    label: 'Resources',
    items: [{ to: '/docs', label: 'Documentation', icon: ICON.docs }],
  },
];

const REGISTRATIONS: NavItem = { to: '/registrations', label: 'Registrations', icon: ICON.registrations };
const APPROVALS: NavItem = { to: '/approvals', label: 'Approvals', icon: ICON.approvals };

/**
 * The navigation for this caller. With governed actions off it is exactly `PORTAL_NAV`. With
 * them on, Platform control gains Registrations, and Approvals for holders of that authority.
 */
export function portalNav(opts: { governedActions: boolean; approver: boolean }): NavSection[] {
  if (!opts.governedActions) return PORTAL_NAV;
  return PORTAL_NAV.map((section) =>
    section.id === 'platform-control'
      ? { ...section, items: [...section.items, REGISTRATIONS, ...(opts.approver ? [APPROVALS] : [])] }
      : section,
  );
}

export function isNavItemActive(item: NavItem, pathname: string): boolean {
  if (item.exact) return pathname === item.to;
  return pathname === item.to || pathname.startsWith(`${item.to}/`);
}

/** Every navigation destination, in display order. */
export function navRoutes(sections: NavSection[] = PORTAL_NAV): string[] {
  return sections.flatMap((s) => s.items.map((i) => i.to));
}
