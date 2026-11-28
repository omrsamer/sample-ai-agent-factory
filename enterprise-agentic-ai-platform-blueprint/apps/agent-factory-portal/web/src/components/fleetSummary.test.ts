// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import type { Agent, FleetSummary } from '../api/client';
import { INCOMPLETE_NOTE, attentionList, attentionTiles, gatewaysLine, partitionTiles, riskTiles, summaryNotes } from './fleetSummary';

// The shape of the first live fleet: 2 registered and waiting for approval, 9 only detected.
const SUMMARY: FleetSummary = {
  generated_at: '2026-03-01T10:00:00Z',
  agents_total: 12,
  by_inventory_state: { registered_and_detected: 8, registered_only: 1, detected_only: 3 },
  by_lifecycle: { approved: 6, pending_approval: 2, proposed: 1, discovered: 3 },
  by_risk_level: { critical: 1, high: 3, medium: 2, low: 6 },
  flags: { unmanaged: 6, ownerless: 2, review_overdue: 0, inactive: 4, contained: 1 },
  flags_unknown: { unmanaged: 0, ownerless: 3, review_overdue: 3, inactive: 5, contained: 2 },
  gateways_total: 2,
  organization_registry: 'ok',
  unreachable_cells: 0,
  inactive_days: 30,
};

const agent = (over: Partial<Agent>): Agent =>
  ({
    id: 'a',
    name: 'a',
    mcp_server_ids: [],
    origin: 'Deployed',
    identity_status: 'none',
    lifecycle_state: 'approved',
    auth_type: 'none',
    created_at: '',
    updated_at: '',
    flags: { unmanaged: false, ownerless: false, review_overdue: false, inactive: false, contained: false },
    risk: { level: 'low', reasons: [] },
    ...over,
  }) as Agent;

describe('partitionTiles', () => {
  it('splits the inventory into approved, awaiting approval and not registered', () => {
    expect(partitionTiles(SUMMARY).map((t) => [t.label, t.value, t.to])).toEqual([
      ['Agents', 12, '/agents'],
      ['Approved', 6, '/agents?lifecycle=approved'],
      ['Awaiting approval', 3, '/agents?lifecycle=awaiting'],
      ['Not registered', 3, '/agents?state=detected_only'],
    ]);
  });

  it('adds up to the total, whatever the mix', () => {
    const live = { ...SUMMARY, agents_total: 11, by_inventory_state: { registered_and_detected: 2, registered_only: 0, detected_only: 9 }, by_lifecycle: { pending_approval: 2, discovered: 9 } };
    for (const summary of [SUMMARY, live]) {
      const [total, ...parts] = partitionTiles(summary).map((t) => t.value ?? Number.NaN);
      expect(parts.reduce((a, b) => a + b, 0)).toBe(total);
    }
    // A lifecycle state that does not occur is absent from the map: that is zero, not unknown.
    expect(partitionTiles(live).map((t) => t.value)).toEqual([11, 0, 2, 9]);
  });

  it('never uses the word "unmanaged", and words the parts as they are', () => {
    const tiles = partitionTiles(SUMMARY);
    expect(tiles.map((t) => `${t.label} ${t.hint}`).join(' ')).not.toMatch(/unmanaged/i);
    expect(tiles.map((t) => t.hint)).toEqual([
      'Registered or detected.',
      'Registered and approved.',
      'Registered, not approved yet.',
      'Running, nobody registered it.',
    ]);
  });

  it('says so when the registrations that are not approved include rejected ones', () => {
    const tiles = partitionTiles({ ...SUMMARY, by_lifecycle: { approved: 6, pending_approval: 2, rejected: 1, discovered: 3 } });
    expect(tiles[2]).toMatchObject({ value: 3, hint: 'Registered, not approved yet. Includes 1 rejected.' });
  });

  it('gives retired registrations a tile of their own, only when there is one, and still adds up', () => {
    expect(partitionTiles(SUMMARY).map((t) => t.id)).toEqual(['agents', 'approved', 'awaiting', 'not_registered']);
    const withRetired = partitionTiles({ ...SUMMARY, by_lifecycle: { approved: 5, pending_approval: 2, deprecated: 2, discovered: 3 } });
    expect(withRetired.map((t) => [t.label, t.value, t.to])).toEqual([
      ['Agents', 12, '/agents'],
      ['Approved', 5, '/agents?lifecycle=approved'],
      ['Awaiting approval', 2, '/agents?lifecycle=awaiting'],
      ['Not registered', 3, '/agents?state=detected_only'],
      ['Retired', 2, '/agents?lifecycle=deprecated'],
    ]);
    const [total, ...parts] = withRetired.map((t) => t.value ?? Number.NaN);
    expect(parts.reduce((a, b) => a + b, 0)).toBe(total);
    // A retired registration is not waiting for approval.
    expect(withRetired[2].hint).toBe('Registered, not approved yet.');
  });

  it('shows what it cannot work out as unknown, not as zero', () => {
    const tiles = partitionTiles({ agents_total: 3 });
    expect(tiles.map((t) => t.value)).toEqual([3, null, null, null]);
    expect(partitionTiles(null).every((t) => t.value === null)).toBe(true);
    // Counts that do not add up are not forced into a negative number.
    expect(partitionTiles({ agents_total: 2, by_lifecycle: { approved: 2 }, by_inventory_state: { detected_only: 1 } })[2].value).toBeNull();
  });
});

describe('attentionTiles', () => {
  it('lists contained, ownerless, review overdue and inactive, each linking to its agents', () => {
    expect(attentionTiles({ ...SUMMARY, by_inventory_state: { ...SUMMARY.by_inventory_state, registered_only: 0 } }).map((t) => [t.label, t.value, t.to])).toEqual([
      ['Contained', 1, '/agents?flag=contained'],
      ['Ownerless', 2, '/agents?flag=ownerless'],
      ['Review overdue', 0, '/agents?flag=review_overdue'],
      ['Inactive', 4, '/agents?flag=inactive'],
    ]);
  });

  it('adds "Registered, not running" only when there is one', () => {
    expect(attentionTiles(SUMMARY).at(-1)).toMatchObject({ label: 'Registered, not running', value: 1, to: '/agents?state=registered_only' });
    expect(attentionTiles({ agents_total: 0 }).map((t) => t.id)).toEqual(['contained', 'ownerless', 'review_overdue', 'inactive']);
  });

  it('counts what could not be read separately, and only for what a reader reads', () => {
    const tiles = attentionTiles(SUMMARY);
    expect(tiles.find((t) => t.id === 'inactive')?.unreadable).toEqual({ count: 5, to: '/agents?flag=inactive:unknown' });
    expect(tiles.find((t) => t.id === 'contained')?.unreadable).toEqual({ count: 2, to: '/agents?flag=contained:unknown' });
    // Ownership and review do not apply to an agent with no registration: that is not "unreadable".
    expect(tiles.find((t) => t.id === 'ownerless')?.unreadable).toBeUndefined();
    expect(tiles.find((t) => t.id === 'review_overdue')?.unreadable).toBeUndefined();
  });

  it('words ownerless as the API defines it and states the inactivity window', () => {
    const tiles = attentionTiles(SUMMARY);
    expect(tiles.find((t) => t.id === 'ownerless')?.hint).toBe('No owner group, or one that is not in the owner roster.');
    expect(tiles.find((t) => t.id === 'inactive')?.hint).toBe('No invocation in 30 days.');
    expect(attentionTiles({ agents_total: 0 }).find((t) => t.id === 'inactive')?.hint).toBe('No invocation in the inactivity window.');
  });

  it('shows a missing count as unknown, not as zero', () => {
    expect(attentionTiles({ agents_total: 3 }).every((t) => t.value === null)).toBe(true);
  });
});

describe('riskTiles', () => {
  it('lists the four levels in words, most severe first, each linking to its agents', () => {
    expect(riskTiles(SUMMARY).map((t) => [t.label, t.value, t.to])).toEqual([
      ['Critical risk', 1, '/agents?risk=critical'],
      ['High risk', 3, '/agents?risk=high'],
      ['Medium risk', 2, '/agents?risk=medium'],
      ['Low risk', 6, '/agents?risk=low'],
    ]);
  });

  it('shows a level the API did not count as unknown', () => {
    expect(riskTiles({ agents_total: 1, by_risk_level: { high: 1 } }).map((t) => t.value)).toEqual([null, 1, null, null]);
  });

  it('leaves out of a level the agents to which no risk rule applies, once the agents are known', () => {
    // The API counts a retired registration with nothing deployed at low; it carries no badge.
    const closed = agent({ id: 'c1', lifecycle_state: 'deprecated', obligations_closed: true, risk: { level: 'low', reasons: [] } });
    const low = agent({ id: 'l1', risk: { level: 'low', reasons: [] } });
    expect(riskTiles(SUMMARY, [closed, closed, low]).map((t) => t.value)).toEqual([1, 3, 2, 4]);
    // Without the agents the API's count stands, and a count never goes below zero.
    expect(riskTiles(SUMMARY, null).map((t) => t.value)).toEqual([1, 3, 2, 6]);
    expect(riskTiles({ agents_total: 1, by_risk_level: { low: 0 } }, [closed]).map((t) => t.value)).toEqual([null, null, null, 0]);
    // A level the API did not count stays unknown.
    expect(riskTiles({ agents_total: 1, by_risk_level: { high: 1 } }, [closed]).map((t) => t.value)).toEqual([null, 1, null, null]);
  });
});

describe('summaryNotes', () => {
  it('is silent when the summary is complete', () => {
    expect(summaryNotes(SUMMARY)).toEqual([]);
    expect(summaryNotes({ ...SUMMARY, organization_registry: 'disabled' })).toEqual([]);
  });

  it('shows the API’s own warnings as sent and adds what they mean for the counts, once', () => {
    const warnings = ['2 cell account(s) could not be read.', 'The organization registry could not be read (AccessDenied).'];
    expect(summaryNotes({ ...SUMMARY, unreachable_cells: 2, organization_registry: 'AccessDenied', warnings })).toEqual([...warnings, INCOMPLETE_NOTE]);
  });

  it('puts the counters into words itself when the API sent no warning', () => {
    expect(summaryNotes({ ...SUMMARY, unreachable_cells: 2, organization_registry: 'AccessDenied' })).toEqual([
      '2 cell accounts could not be read.',
      'The organization registry could not be read (AccessDenied).',
      INCOMPLETE_NOTE,
    ]);
    expect(summaryNotes({ ...SUMMARY, unreachable_cells: 1 })).toEqual(['1 cell account could not be read.', INCOMPLETE_NOTE]);
    expect(summaryNotes({ ...SUMMARY, unreachable_cells: 1, warnings: ['', '  '] })[0]).toBe('1 cell account could not be read.');
  });

  it('says that review dates fall back to the registrations’ own when the attestations could not be read', () => {
    expect(summaryNotes({ ...SUMMARY, review_attestations: 'AccessDeniedException' })).toEqual([
      'The review attestations could not be read (AccessDeniedException), so every review date shown is the registration’s own.',
    ]);
    // The API's own warning is shown as sent, and the counts are not called incomplete for it.
    const warning = 'Review attestations could not be read (AccessDeniedException); each review date shown is the registration’s own.';
    expect(summaryNotes({ ...SUMMARY, review_attestations: 'AccessDeniedException', warnings: [warning] })).toEqual([warning]);
    expect(summaryNotes({ ...SUMMARY, review_attestations: 'disabled' })).toEqual([]);
    expect(summaryNotes({ ...SUMMARY, review_attestations: 'ok' })).toEqual([]);
  });

  it('passes on a warning about something else without calling the counts incomplete', () => {
    expect(summaryNotes({ ...SUMMARY, warnings: ['Extra note.'] })).toEqual(['Extra note.']);
    expect(summaryNotes(null)).toEqual([]);
  });
});

describe('a retired registration with nothing deployed', () => {
  it('is never in Needs attention, whatever its record still says', () => {
    const closed = agent({ id: 'closed', name: 'closed', lifecycle_state: 'deprecated', obligations_closed: true, risk: { level: 'low', reasons: [] }, flags: { unmanaged: null, ownerless: null, review_overdue: null, inactive: null, contained: null } });
    // Even with a stale level or flag on it, closed wins: nothing can be done about it.
    const stale = agent({ id: 'stale', name: 'stale', lifecycle_state: 'deprecated', obligations_closed: true, risk: { level: 'high', reasons: [] }, flags: { ownerless: true } });
    const open = agent({ id: 'open', name: 'open', risk: { level: 'high', reasons: [] } });
    const list = attentionList([closed, stale, open], 10);
    expect(list.total).toBe(1);
    expect(list.shown.map((entry) => entry.agent.id)).toEqual(['open']);
  });
});

describe('gatewaysLine', () => {
  it('counts the tool gateways and says how many enforce policy', () => {
    expect(gatewaysLine({ ...SUMMARY, gateways_total: 3, gateways_by_policy_mode: { enforce: 1, log_only: 2, none: 0 } })).toBe(
      '3 tool gateways serve these agents: 1 enforcing policy, 2 only logging policy decisions.',
    );
    expect(gatewaysLine({ ...SUMMARY, gateways_total: 1, gateways_by_policy_mode: { enforce: 0, log_only: 0, none: 1 } })).toBe(
      '1 tool gateway serves these agents: 1 with no policy engine.',
    );
  });

  it('counts the gateways no reader read on their own, never as having no policy engine', () => {
    const line = gatewaysLine({ ...SUMMARY, gateways_total: 12, gateways_by_policy_mode: { enforce: 1, log_only: 2, none: 0, unknown: 9 } });
    expect(line).toBe('12 tool gateways are known: 1 enforcing policy, 2 only logging policy decisions, 9 whose policy cannot be read.');
    expect(line).not.toMatch(/no policy engine|serve these agents/);
    expect(gatewaysLine({ ...SUMMARY, gateways_total: 1, gateways_by_policy_mode: { unknown: 1 } })).toBe(
      '1 tool gateway is known: 1 whose policy cannot be read.',
    );
    // None of them: the sentence is what it was.
    expect(gatewaysLine({ ...SUMMARY, gateways_total: 3, gateways_by_policy_mode: { enforce: 1, log_only: 2, none: 0, unknown: 0 } })).toBe(
      '3 tool gateways serve these agents: 1 enforcing policy, 2 only logging policy decisions.',
    );
  });

  it('counts a mode it does not know under its own name', () => {
    expect(gatewaysLine({ ...SUMMARY, gateways_total: 2, gateways_by_policy_mode: { enforce: 1, shadow: 1 } })).toBe(
      '2 tool gateways serve these agents: 1 enforcing policy, 1 in mode shadow.',
    );
  });

  it('gives the count alone when the modes are not reported, and nothing when the count is not', () => {
    expect(gatewaysLine(SUMMARY)).toBe('2 tool gateways serve these agents.');
    expect(gatewaysLine({ ...SUMMARY, gateways_total: 0 })).toBe('0 tool gateways serve these agents.');
    expect(gatewaysLine({ ...SUMMARY, gateways_total: null })).toBeNull();
    expect(gatewaysLine(null)).toBeNull();
  });
});

describe('attentionList', () => {
  const agents = [
    agent({ id: 'low', name: 'quiet' }),
    agent({ id: 'crit', name: 'zeta', risk: { level: 'critical', reasons: [] } }),
    agent({ id: 'owner', name: 'beta', flags: { ownerless: true } }),
    agent({ id: 'high', name: 'alpha', risk: { level: 'high', reasons: [] } }),
    agent({ id: 'held', name: 'gamma', risk: { level: 'high', reasons: [] }, flags: { contained: true } }),
    agent({ id: 'idle', name: 'idle', flags: { inactive: true } }),
    agent({ id: 'unknown', name: 'unknown', flags: { unmanaged: null, ownerless: null } }),
    agent({ id: 'waiting', name: 'waiting', lifecycle_state: 'pending_approval', risk: { level: 'medium', reasons: [] }, flags: { unmanaged: true } }),
  ];

  it('lists high-risk and flagged agents, most severe first, then contained, then by name', () => {
    const { shown, total } = attentionList(agents, 10);
    expect(shown.map((e) => e.agent.id)).toEqual(['crit', 'held', 'high', 'owner']);
    expect(total).toBe(4);
  });

  it('leaves out agents that are only inactive, low risk, or whose flags are unknown', () => {
    const ids = attentionList(agents, 10).shown.map((e) => e.agent.id);
    expect(ids).not.toContain('idle');
    expect(ids).not.toContain('low');
    expect(ids).not.toContain('unknown');
  });

  it('does not list a registration for waiting for approval alone', () => {
    expect(attentionList(agents, 10).shown.map((e) => e.agent.id)).not.toContain('waiting');
  });

  it('keeps two agents of one name in a stable order', () => {
    const twins = [
      agent({ id: 'b-ws2', name: 'travel-agent', risk: { level: 'high', reasons: [] } }),
      agent({ id: 'a-ws1', name: 'travel-agent', risk: { level: 'high', reasons: [] } }),
    ];
    expect(attentionList(twins, 5).shown.map((e) => e.agent.id)).toEqual(['a-ws1', 'b-ws2']);
    expect(attentionList([...twins].reverse(), 5).shown.map((e) => e.agent.id)).toEqual(['a-ws1', 'b-ws2']);
  });

  it('limits what is shown and reports the full count', () => {
    const { shown, total } = attentionList(agents, 2);
    expect(shown).toHaveLength(2);
    expect(total).toBe(4);
    expect(attentionList(null, 5)).toEqual({ shown: [], total: 0 });
  });
});
