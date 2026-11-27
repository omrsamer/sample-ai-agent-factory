// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { CellHealthState, FleetCell, FleetHealth } from '../api/client';

export const CELL_STATES: readonly CellHealthState[] = ['critical', 'needs_attention', 'no_data', 'healthy'];

const STATE_VIEW: Record<CellHealthState, { label: string; cls: string; dot: string }> = {
  healthy: { label: 'Healthy', cls: 'bg-emerald-50 text-emerald-700', dot: 'bg-emerald-500' },
  needs_attention: { label: 'Needs attention', cls: 'bg-amber-50 text-amber-700', dot: 'bg-amber-500' },
  critical: { label: 'Critical', cls: 'bg-red-50 text-red-700', dot: 'bg-red-500' },
  no_data: { label: 'No data', cls: 'bg-slate-100 text-slate-600', dot: 'bg-slate-400' },
};

/** Badge for a cell state. An unrecognised value reads as "No data", never as healthy. */
export function cellStateView(state: string): { label: string; cls: string; dot: string } {
  return Object.prototype.hasOwnProperty.call(STATE_VIEW, state)
    ? STATE_VIEW[state as CellHealthState]
    : STATE_VIEW.no_data;
}

function severity(state: string): number {
  const index = CELL_STATES.indexOf(state as CellHealthState);
  // Unknown states sort with "no data".
  return index === -1 ? CELL_STATES.indexOf('no_data') : index;
}

/** Worst first, then by tenant, agent and environment, so the list is stable between loads. */
export function sortCells(cells: readonly FleetCell[]): FleetCell[] {
  return [...cells].sort(
    (a, b) =>
      severity(a.state) - severity(b.state) ||
      a.tenant_id.localeCompare(b.tenant_id) ||
      a.agent_id.localeCompare(b.agent_id) ||
      a.environment.localeCompare(b.environment),
  );
}

/**
 * Totals per state. Uses the totals the API sent when they are complete; otherwise counts the
 * cells, so a partial `totals` object cannot show a zero that the list contradicts.
 */
export function fleetTotals(health: Pick<FleetHealth, 'cells' | 'totals'> | null): Record<CellHealthState, number> {
  const counted: Record<CellHealthState, number> = { healthy: 0, needs_attention: 0, critical: 0, no_data: 0 };
  if (!health) return counted;
  const sent = health.totals as Partial<Record<CellHealthState, unknown>> | undefined;
  if (sent && CELL_STATES.every((s) => typeof sent[s] === 'number')) {
    return sent as Record<CellHealthState, number>;
  }
  for (const cell of health.cells ?? []) {
    const key = Object.prototype.hasOwnProperty.call(counted, cell.state) ? cell.state : 'no_data';
    counted[key] += 1;
  }
  return counted;
}
