// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { Fragment, type ReactElement } from 'react';
import type { LifecycleState, McpServerKind } from '../../api/client';

const LIFECYCLE_BADGE_CLS: Record<LifecycleState, string> = {
  approved: 'bg-emerald-50 text-emerald-700',
  proposed: 'bg-slate-100 text-slate-600',
  pending_approval: 'bg-amber-50 text-amber-700',
  rejected: 'bg-red-50 text-red-700',
  deprecated: 'bg-slate-100 text-slate-600',
  discovered: 'bg-sky-50 text-sky-700',
};

const LIFECYCLE_LABEL: Record<LifecycleState, string> = {
  approved: 'Approved',
  proposed: 'Proposed',
  pending_approval: 'Pending approval',
  rejected: 'Rejected',
  // The registry's word is DEPRECATED; the portal calls such a registration retired.
  deprecated: 'Retired',
  discovered: 'Discovered, not registered',
};

export const LIFECYCLE_OPTIONS: { value: LifecycleState; label: string }[] = (
  Object.keys(LIFECYCLE_LABEL) as LifecycleState[]
).map((value) => ({ value, label: LIFECYCLE_LABEL[value] }));

/** Badge for a lifecycle state. A value this build does not know is shown as recorded. */
export function lifecycleBadge(state: LifecycleState | string): { cls: string; label: string } {
  if (Object.prototype.hasOwnProperty.call(LIFECYCLE_LABEL, state)) {
    const known = state as LifecycleState;
    return { cls: LIFECYCLE_BADGE_CLS[known], label: LIFECYCLE_LABEL[known] };
  }
  return { cls: 'bg-slate-100 text-slate-600', label: state || 'Unknown' };
}

export function kindBadge(kind: McpServerKind): { cls: string; label: string } {
  if (kind === 'gateway') return { cls: 'bg-violet-50 text-violet-700', label: 'Gateway' };
  if (kind === 'runtime') return { cls: 'bg-indigo-50 text-indigo-700', label: 'Runtime' };
  return { cls: 'bg-slate-100 text-slate-600', label: 'Standard' };
}

export function tenantBadge(name?: string | null): { cls: string; label: string } {
  const trimmed = (name ?? '').trim();
  if (!trimmed) return { cls: 'bg-slate-100 text-slate-600', label: 'None' };
  return { cls: 'bg-teal-50 text-teal-700', label: trimmed };
}

/** The pieces of a name, each ending at a hyphen or an underscore, where a line may break. */
export function nameSegments(name: string): string[] {
  return name.match(/[^-_]*[-_]+|[^-_]+$/g) ?? [];
}

/**
 * An agent or cell name that wraps only at hyphens, underscores and spaces, never in the
 * middle of a word.
 */
export function BreakableName({ name }: { name: string }): ReactElement {
  const segments = nameSegments(name);
  return (
    <>
      {segments.map((segment, i) => (
        <Fragment key={i}>
          {segment}
          {i < segments.length - 1 && <wbr />}
        </Fragment>
      ))}
    </>
  );
}

const AVATAR_PALETTE: string[] = [
  'bg-blue-100 text-blue-700',
  'bg-emerald-100 text-emerald-700',
  'bg-violet-100 text-violet-700',
  'bg-amber-100 text-amber-700',
  'bg-rose-100 text-rose-700',
  'bg-cyan-100 text-cyan-700',
  'bg-indigo-100 text-indigo-700',
  'bg-teal-100 text-teal-700',
];

const AVATAR_SIZE: Record<'sm' | 'md' | 'lg', string> = {
  sm: 'h-7 w-7 text-xs',
  md: 'h-9 w-9 text-sm',
  lg: 'h-12 w-12 text-base',
};

export function initialsFor(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) return '?';
  const segments = trimmed.split(/[\s._-]+/).filter(Boolean);
  if (segments.length >= 2) {
    return (segments[0][0] + segments[1][0]).toUpperCase();
  }
  const single = segments[0] ?? trimmed;
  return single.slice(0, 2).toUpperCase();
}

function hashIndex(name: string, modulo: number): number {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  }
  return hash % modulo;
}

export function AgentAvatar({
  name,
  size = 'md',
}: {
  name: string;
  size?: 'sm' | 'md' | 'lg';
}): ReactElement {
  const base = `${AVATAR_SIZE[size]} rounded-lg font-semibold flex items-center justify-center shrink-0`;
  const trimmed = (name ?? '').trim();
  if (!trimmed) {
    return <div aria-hidden="true" className={`${base} bg-slate-100 text-slate-600`}>?</div>;
  }
  const color = AVATAR_PALETTE[hashIndex(trimmed, AVATAR_PALETTE.length)];
  return (
    <div aria-hidden="true" className={`${base} ${color}`}>
      {initialsFor(trimmed)}
    </div>
  );
}
