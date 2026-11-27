// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import type { AgentMetrics, TraceRow } from '../../../types';
import { buildDashboardSeries, type DashboardSeries, type DateRange } from '../observability/observabilityMetrics';

/** Pure formatting for the per-agent Traces and Cost tabs. */

export const EM_DASH = '—';

export interface TraceDisplayRow {
  id: string;
  timestamp: string;
  name: string;
  latency: string;
  cost: string;
  tokens: string;
  status: string;
  user: string;
  raw: TraceRow;
}

/** US dollars, with enough digits that a sub-cent cost is not rounded away to zero. */
export const fmtUsd = (n: number): string => {
  const digits = n === 0 ? 2 : Math.abs(n) < 0.01 ? 6 : Math.abs(n) < 1 ? 4 : 2;
  return `$${n.toLocaleString(undefined, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })}`;
};

export const COST_UNAVAILABLE = 'Not available';
export const COST_UNAVAILABLE_NOTE =
  'Cost is not available from this telemetry source. Trace and token counts are shown; cost figures are omitted.';

/** A cost figure, or "Not available" when the source cannot price usage. Absent flag means available. */
export function costText(n: number, costAvailable: boolean | undefined): string {
  return costAvailable === false ? COST_UNAVAILABLE : fmtUsd(n);
}

function fmtTimestamp(iso: string | null): string {
  if (!iso) return EM_DASH;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function fmtLatency(ms: number | null): string {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return EM_DASH;
  return `${Math.round(ms).toLocaleString()} ms`;
}

export function mapTraceRows(rows: TraceRow[]): TraceDisplayRow[] {
  return rows.map((r) => ({
    id: r.id,
    timestamp: fmtTimestamp(r.timestamp),
    name: r.name ?? EM_DASH,
    latency: fmtLatency(r.latency_ms),
    // A zero cost on a trace means "not priced", so it is shown as a dash rather than $0.00.
    cost: r.cost_usd ? fmtUsd(r.cost_usd) : EM_DASH,
    tokens: typeof r.total_tokens === 'number' ? r.total_tokens.toLocaleString() : EM_DASH,
    status: r.status ?? EM_DASH,
    user: r.user_id ?? EM_DASH,
    raw: r,
  }));
}

export function totalPages(total: number, pageSize: number): number {
  if (pageSize <= 0) return 1;
  return Math.max(1, Math.ceil(total / pageSize));
}

/** One agent's metrics in the dashboard's series shape. A single agent has no per-agent rows. */
export function agentMetricsToSeries(
  metrics: AgentMetrics | null | undefined,
  range?: DateRange,
): DashboardSeries {
  return buildDashboardSeries(metrics ? { ...metrics, by_agent: [] } : metrics, range);
}
