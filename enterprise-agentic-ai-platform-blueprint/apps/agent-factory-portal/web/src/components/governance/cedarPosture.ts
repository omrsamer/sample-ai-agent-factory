// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import type { CedarEnforcementMode } from '../../api/client';

/** Wording for a tool gateway's Cedar enforcement mode. Pure, so the copy is unit tested. */
export interface EnforcementView {
  ring: string;
  dot: string;
  heading: string;
  body: string;
}

const ENFORCEMENT_VIEW: Record<CedarEnforcementMode, EnforcementView> = {
  none: {
    ring: 'border-slate-200/70',
    dot: 'bg-slate-400',
    heading: 'No policy engine attached',
    body: 'Cedar policies are not evaluated on this gateway. Any caller that IAM authorises can call any of its tools.',
  },
  log_only: {
    ring: 'border-amber-200/80',
    dot: 'bg-amber-500',
    heading: 'Logging only',
    body: 'Policies are evaluated and each decision is logged, but nothing is blocked. Any caller that IAM authorises can still call any tool.',
  },
  enforce: {
    ring: 'border-emerald-200/80',
    dot: 'bg-emerald-500',
    heading: 'Enforcing (default deny)',
    body: 'Only tool calls a policy permits go through. A call no policy covers is blocked.',
  },
};

const MODES: ReadonlyMap<string, CedarEnforcementMode> = new Map(
  (Object.keys(ENFORCEMENT_VIEW) as CedarEnforcementMode[]).map((m) => [m, m]),
);

/** Narrows a wire value to a known mode. Anything else is `null`, never assumed to be enforcing. */
export function toEnforcementMode(raw: string | null | undefined): CedarEnforcementMode | null {
  return MODES.get((raw ?? '').trim().toLowerCase()) ?? null;
}

export const UNKNOWN_ENFORCEMENT_VIEW: EnforcementView = {
  ring: 'border-slate-200/70',
  dot: 'bg-slate-300',
  heading: 'Enforcement mode unknown',
  body: 'The gateway did not report an enforcement mode, so this page cannot say whether policies are applied.',
};

export function enforcementView(raw: string | null | undefined): EnforcementView {
  const mode = toEnforcementMode(raw);
  return mode ? ENFORCEMENT_VIEW[mode] : UNKNOWN_ENFORCEMENT_VIEW;
}

export const ENFORCE_POSTURE_WARNING =
  'Every tool call not covered by a policy below is blocked, for every agent connected ' +
  'to this gateway. A blocked call reaches the agent as a tool error naming the policy id. ' +
  'An empty policy list under enforcement blocks every call.';

/** Extra caution shown only while enforcing. */
export function postureWarning(raw: string | null | undefined): string | null {
  return toEnforcementMode(raw) === 'enforce' ? ENFORCE_POSTURE_WARNING : null;
}

/** Short label for tables and the access graph. */
export function enforcementLabel(raw: string | null | undefined): string {
  return enforcementView(raw).heading;
}
