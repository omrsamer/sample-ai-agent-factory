// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { Agent } from '../../api/client';
import { Badge } from '../shared/ui';
import { CLOSED_RISK_NOTE, NOT_APPLICABLE, agentChips, inventoryStateTag, isContained, obligationsClosed, riskTag, type Tag } from './inventory';

function TagBadge({ tag }: { tag: Tag }) {
  return (
    <>
      <Badge cls={tag.cls} label={tag.label} title={tag.hint} />
      {tag.hint && <span className="sr-only"> {tag.hint}</span>}
    </>
  );
}

/** "Registered", "Not registered" or "Registered, not running". */
export function InventoryStateBadge({ state }: { state: string | null | undefined }) {
  return <TagBadge tag={inventoryStateTag(state)} />;
}

/** The risk level in words. Colour supports the label and never replaces it. */
export function RiskBadge({ level }: { level: string | null | undefined }) {
  return <TagBadge tag={riskTag(level)} />;
}

/**
 * An agent's risk level. A retired registration with nothing deployed has none: no risk rule
 * applies to it, so no badge is shown. In a table cell that is said in words instead.
 */
export function AgentRisk({ agent, inWords = false }: { agent: Pick<Agent, 'risk' | 'obligations_closed'>; inWords?: boolean }) {
  if (obligationsClosed(agent)) {
    return inWords ? <span className="text-slate-600" title={CLOSED_RISK_NOTE}>{NOT_APPLICABLE}</span> : null;
  }
  return <RiskBadge level={agent.risk?.level} />;
}

/**
 * The chips for what needs attention on an agent and for what cannot be read about it, as text.
 * See `agentChips` for which are shown.
 */
export function AgentChips({ agent }: { agent: Parameters<typeof agentChips>[0] }) {
  const tags = agentChips(agent);
  if (tags.length === 0) return null;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {tags.map((tag) => (
        <TagBadge key={tag.label} tag={tag} />
      ))}
    </span>
  );
}

/**
 * The containment marker. It is shown wherever a contained agent appears, in words, with an
 * icon that is decoration only.
 */
export function ContainedBadge({ agent }: { agent: Pick<Agent, 'flags'> | null | undefined }) {
  if (!isContained(agent)) return null;
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-700 text-white shrink-0"
      title="New invocations are denied until the agent is released."
    >
      <svg viewBox="0 0 20 20" fill="currentColor" className="h-3 w-3" aria-hidden="true">
        <path d="M10 2a4 4 0 0 0-4 4v2H5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V9a1 1 0 0 0-1-1h-1V6a4 4 0 0 0-4-4Zm-2 6V6a2 2 0 1 1 4 0v2H8Z" />
      </svg>
      Contained
    </span>
  );
}
