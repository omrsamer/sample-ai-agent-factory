// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { Agent, FleetSummary } from '../api/client';
import { AWAITING_APPROVAL, RISK_LEVELS, flagHint, flagLabel, flagState, type FlagName, obligationsClosed } from './governance/inventory';

/** Pure view rules for the fleet home: the tiles and the "Needs attention" list. */

export type TileTone = 'critical' | 'attention' | undefined;

export interface SummaryTile {
  id: string;
  label: string;
  /** The count, or null when it is not known. Null is shown in words, never as zero. */
  value: number | null;
  /** Where the tile leads: the agents list, filtered to what it counts. */
  to: string;
  hint: string;
  tone: TileTone;
  /** Agents for which this could not be read, and where to see them. */
  unreadable?: { count: number; to: string };
}

function count(map: Record<string, number> | null | undefined, key: string): number | null {
  const value = map?.[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** A count from a map that lists only what occurs: a missing key is zero, a missing map is unknown. */
function occurring(map: Record<string, number> | null | undefined, key: string): number | null {
  if (!map) return null;
  return count(map, key) ?? 0;
}

/**
 * The first row of tiles: a partition of the inventory that adds up to its total. Every agent
 * is approved, registered and not approved yet, not registered at all, or retired. The retired
 * tile is listed only when there is one.
 */
export function partitionTiles(summary: FleetSummary | null | undefined): SummaryTile[] {
  const total = typeof summary?.agents_total === 'number' ? summary.agents_total : null;
  const approved = occurring(summary?.by_lifecycle, 'approved');
  const notRegistered = count(summary?.by_inventory_state, 'detected_only');
  const retired = occurring(summary?.by_lifecycle, 'deprecated') ?? 0;
  const rest = total !== null && approved !== null && notRegistered !== null ? total - approved - notRegistered - retired : null;
  const awaiting = rest !== null && rest >= 0 ? rest : null;
  // A registration that was decided against is registered and not approved too.
  const rejected = occurring(summary?.by_lifecycle, 'rejected') ?? 0;
  const tiles: SummaryTile[] = [
    { id: 'agents', label: 'Agents', value: total, to: '/agents', hint: 'Registered or detected.', tone: undefined },
    { id: 'approved', label: 'Approved', value: approved, to: '/agents?lifecycle=approved', hint: 'Registered and approved.', tone: undefined },
    {
      id: 'awaiting',
      label: 'Awaiting approval',
      value: awaiting,
      to: `/agents?lifecycle=${AWAITING_APPROVAL}`,
      hint: rejected > 0 && awaiting !== null ? `Registered, not approved yet. Includes ${rejected} rejected.` : 'Registered, not approved yet.',
      tone: 'attention',
    },
    {
      id: 'not_registered',
      label: 'Not registered',
      value: notRegistered,
      to: '/agents?state=detected_only',
      hint: 'Running, nobody registered it.',
      tone: 'critical',
    },
  ];
  if (retired > 0) {
    tiles.push({ id: 'retired', label: 'Retired', value: retired, to: '/agents?lifecycle=deprecated', hint: 'Registration retired for good.', tone: undefined });
  }
  return tiles;
}

const FLAG_TILES: { name: FlagName; hint?: string; tone: TileTone; readerFact: boolean }[] = [
  { name: 'contained', hint: 'Invocations are denied.', tone: 'critical', readerFact: true },
  { name: 'ownerless', tone: 'attention', readerFact: false },
  { name: 'review_overdue', hint: 'Review date has passed.', tone: 'attention', readerFact: false },
  { name: 'inactive', tone: undefined, readerFact: true },
];

/**
 * The second row: what needs attention. "Registered, not running" is listed only when there is
 * one. Containment and activity are read by a reader role, so those two tiles also say for how
 * many agents they could not be read; ownership and review do not apply to an agent with no
 * registration, so nothing is called unreadable there.
 */
export function attentionTiles(summary: FleetSummary | null | undefined): SummaryTile[] {
  const inactiveDays = summary?.inactive_days;
  const tiles: SummaryTile[] = FLAG_TILES.map(({ name, hint, tone, readerFact }) => {
    const unreadable = readerFact ? count(summary?.flags_unknown, name) ?? 0 : 0;
    return {
      id: name,
      label: flagLabel(name),
      value: count(summary?.flags, name),
      to: `/agents?flag=${name}`,
      hint: name === 'inactive' && typeof inactiveDays === 'number' ? `No invocation in ${inactiveDays} days.` : hint ?? flagHint(name),
      tone,
      ...(unreadable > 0 ? { unreadable: { count: unreadable, to: `/agents?flag=${name}:unknown` } } : {}),
    };
  });
  const notRunning = count(summary?.by_inventory_state, 'registered_only') ?? 0;
  if (notRunning > 0) {
    tiles.push({
      id: 'registered_only',
      label: 'Registered, not running',
      value: notRunning,
      to: '/agents?state=registered_only',
      hint: 'No runtime was detected.',
      tone: undefined,
    });
  }
  return tiles;
}

/**
 * One tile per risk level, most severe first.
 *
 * The API counts an agent whose obligations are closed (a retired registration with nothing
 * deployed) at level `low`, although no rule applies to it and it carries no risk badge. When
 * the agents are known, those are taken out of the count, so that a tile counts the agents that
 * carry its badge and its link lists the same ones.
 */
export function riskTiles(summary: FleetSummary | null | undefined, agents?: readonly Agent[] | null): SummaryTile[] {
  const closedAt = (level: string) => (agents ?? []).filter((agent) => obligationsClosed(agent) && agent.risk?.level === level).length;
  return RISK_LEVELS.map((level) => {
    const counted = count(summary?.by_risk_level, level);
    return {
      id: `risk-${level}`,
      label: `${level.charAt(0).toUpperCase()}${level.slice(1)} risk`,
      value: counted === null ? null : Math.max(0, counted - closedAt(level)),
      to: `/agents?risk=${level}`,
      hint: 'Agents at this level.',
      tone: level === 'critical' || level === 'high' ? 'critical' : level === 'medium' ? 'attention' : undefined,
    };
  });
}

export const INCOMPLETE_NOTE = 'These counts may be incomplete: an agent known only from what could not be read is missing.';

/**
 * Things the summary says about its own completeness. The API's own warnings are shown as
 * sent; the two counters are put into words only when it sent none, so nothing is said twice.
 * Whenever something could not be read, one sentence says what that means for the counts.
 */
export function summaryNotes(summary: FleetSummary | null | undefined): string[] {
  const warnings = (summary?.warnings ?? []).filter((w) => typeof w === 'string' && w.trim() !== '');
  const unreachable = summary?.unreachable_cells ?? 0;
  const registry = summary?.organization_registry;
  const registryFailed = !!registry && registry !== 'ok' && registry !== 'disabled';
  const attestations = summary?.review_attestations;
  const attestationsFailed = !!attestations && attestations !== 'ok' && attestations !== 'disabled';
  const notes = [...warnings];
  if (warnings.length === 0) {
    if (unreachable > 0) notes.push(`${unreachable} cell ${unreachable === 1 ? 'account' : 'accounts'} could not be read.`);
    if (registryFailed) notes.push(`The organization registry could not be read (${registry}).`);
    // The counts stand; only the review dates fall back to each registration's own.
    if (attestationsFailed) notes.push(`The review attestations could not be read (${attestations}), so every review date shown is the registration’s own.`);
  }
  if (unreachable > 0 || registryFailed) notes.push(INCOMPLETE_NOTE);
  return notes;
}

const POLICY_MODE: [key: string, words: string][] = [
  ['enforce', 'enforcing policy'],
  ['log_only', 'only logging policy decisions'],
  ['none', 'with no policy engine'],
  // A gateway that only the organization registry detected: no reader read its policy engine.
  // It is counted on its own, never under "no policy engine".
  ['unknown', 'whose policy cannot be read'],
];

/**
 * The tool gateways in one sentence, with how many enforce policy, or null when the summary
 * does not count them. A mode the page does not know is counted under its own name.
 *
 * A gateway whose policy cannot be read is one no reader read, in an account that need not be
 * a cell of this fleet. When there is one the sentence no longer says that the gateways "serve
 * these agents", which is not known of it.
 */
export function gatewaysLine(summary: FleetSummary | null | undefined): string | null {
  const total = summary?.gateways_total;
  if (typeof total !== 'number' || !Number.isFinite(total)) return null;
  const modes = summary?.gateways_by_policy_mode ?? {};
  const unread = (count(modes, 'unknown') ?? 0) > 0;
  const head = unread
    ? `${total} tool ${total === 1 ? 'gateway is' : 'gateways are'} known`
    : `${total} tool ${total === 1 ? 'gateway serves' : 'gateways serve'} these agents`;
  const known = new Set(POLICY_MODE.map(([key]) => key));
  const parts = [
    ...POLICY_MODE.map(([key, words]) => [count(modes, key) ?? 0, words] as const),
    ...Object.keys(modes)
      .filter((key) => !known.has(key))
      .sort()
      .map((key) => [count(modes, key) ?? 0, `in mode ${key}`] as const),
  ]
    .filter(([n]) => n > 0)
    .map(([n, words]) => `${n} ${words}`);
  return parts.length > 0 ? `${head}: ${parts.join(', ')}.` : `${head}.`;
}

const RISK_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
// A registration that only waits for approval is not listed for that alone, and an agent
// nobody registered is at high risk already.
const ATTENTION_FLAGS: readonly FlagName[] = ['contained', 'ownerless', 'review_overdue'];

export interface AttentionEntry {
  agent: Agent;
}

function riskRank(agent: Agent): number {
  const level = agent.risk?.level ?? '';
  return Object.prototype.hasOwnProperty.call(RISK_RANK, level) ? RISK_RANK[level] : 4;
}

/**
 * The agents to look at first: every agent at critical or high risk, and every agent that is
 * contained, ownerless or overdue for review. Most severe first, then contained, then by name
 * and id, so the order is stable between loads and two agents of one name keep their places.
 */
export function attentionList(agents: readonly Agent[] | null | undefined, limit: number): { shown: AttentionEntry[]; total: number } {
  const entries = (agents ?? [])
    .map((agent) => ({
      agent,
      set: ATTENTION_FLAGS.filter((name) => flagState(agent.flags, name) === 'set'),
    }))
    // A retired registration with nothing deployed never asks for attention.
    .filter(({ agent, set }) => !obligationsClosed(agent) && (riskRank(agent) <= 1 || set.length > 0))
    .sort(
      (a, b) =>
        riskRank(a.agent) - riskRank(b.agent) ||
        Number(b.set.includes('contained')) - Number(a.set.includes('contained')) ||
        a.agent.name.localeCompare(b.agent.name) ||
        a.agent.id.localeCompare(b.agent.id),
    );
  return {
    shown: entries.slice(0, limit).map(({ agent }) => ({ agent })),
    total: entries.length,
  };
}
