// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { Deployment } from '../../../api/client';

export interface StatusBadge {
  label: string;
  cls: string;
}

const OK = 'bg-emerald-50 text-emerald-700';
const WARN = 'bg-amber-50 text-amber-700';
const BAD = 'bg-red-50 text-red-700';
const MUTED = 'bg-slate-100 text-slate-600';

const RUNTIME_STATUS: Record<string, StatusBadge> = {
  ready: { label: 'Ready', cls: OK },
  active: { label: 'Ready', cls: OK },
  creating: { label: 'Creating', cls: WARN },
  updating: { label: 'Updating', cls: WARN },
  deleting: { label: 'Deleting', cls: WARN },
  failed: { label: 'Failed', cls: BAD },
  create_failed: { label: 'Create failed', cls: BAD },
  update_failed: { label: 'Update failed', cls: BAD },
  not_deployed: { label: 'Not deployed', cls: MUTED },
};

/**
 * Narrows the free-form runtime status word. Anything unrecognised, empty or absent reads as
 * "Unknown", never as ready.
 */
export function runtimeStatusBadge(status: string | null | undefined): StatusBadge {
  const key = (status ?? '').trim().toLowerCase();
  if (key && Object.prototype.hasOwnProperty.call(RUNTIME_STATUS, key)) return RUNTIME_STATUS[key];
  return { label: 'Unknown', cls: MUTED };
}

const OUTCOME: Record<string, StatusBadge> = {
  succeeded: { label: 'Succeeded', cls: OK },
  failed: { label: 'Failed', cls: BAD },
  started: { label: 'Started', cls: MUTED },
};

export function outcomeBadge(outcome: string | null | undefined): StatusBadge {
  const key = (outcome ?? '').trim().toLowerCase();
  if (key && Object.prototype.hasOwnProperty.call(OUTCOME, key)) return OUTCOME[key];
  return { label: outcome?.trim() || 'Unknown', cls: MUTED };
}

/** Who started a deployment. A row written by the build itself has no actor, shown as a dash. */
export function deploymentActor(row: Pick<Deployment, 'actor' | 'actor_kind'>): string {
  const actor = row.actor?.trim();
  if (!actor) return 'Not recorded';
  return row.actor_kind === 'github' ? `@${actor}` : actor;
}

/** The environments to offer: every key of `agent_arns`, sorted. Empty when none is recorded. */
export function agentEnvironments(agentArns: Record<string, string> | null | undefined): string[] {
  return Object.keys(agentArns ?? {}).sort((a, b) => a.localeCompare(b));
}

export function shortSha(sha: string | null | undefined): string {
  const value = sha?.trim();
  return value ? value.slice(0, 7) : 'Not set';
}
