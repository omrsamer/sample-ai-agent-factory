// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useMemo, useState } from 'react';
import { observabilityApi } from '../../../api/client';
import type { Agent } from '../../../api/client';
import { mapTraceRows, totalPages } from './agentObservability';
import { useAsync } from '../../shared/useAsync';
import { DataNotes, ObsEmptyCard } from './ObsEmptyCard';

const CARD = 'bg-white/70 backdrop-blur rounded-xl border border-slate-200/60 shadow-sm';
const PAGE_SIZE = 20;

/** Recent runs of one agent, newest first, paged by the API. */
export default function TracesTab({ agent }: { agent: Agent }) {
  const agentId = agent.id;
  const [page, setPage] = useState(1);
  const { data, loading, error } = useAsync(
    () => observabilityApi.getAgentTraces(agentId, { page, limit: PAGE_SIZE }),
    [agentId, page],
    'Failed to load traces',
  );
  const rows = useMemo(() => data?.data ?? [], [data]);
  const total = data?.total ?? 0;

  const display = useMemo(() => mapTraceRows(rows), [rows]);
  const pages = totalPages(total, PAGE_SIZE);

  if (error) {
    return <ObsEmptyCard title="Couldn't load traces" body={error} tone="amber" />;
  }

  if (!loading && rows.length === 0 && page === 1) {
    return (
      <ObsEmptyCard
        title="No traces recorded yet"
        body="Once this agent is invoked, each run appears here with its latency, cost and caller, newest first."
      />
    );
  }

  return (
    <div className={`${CARD} p-5`}>
      <div className="mb-3 empty:hidden"><DataNotes notes={data?.warnings ?? []} /></div>
      <div className="flex items-center justify-between mb-3">
        <div className="text-sm font-semibold text-slate-900">Recent traces</div>
        {loading && (
          <div className="flex items-center gap-2 text-xs text-slate-600">
            <span className="w-3.5 h-3.5 border-2 border-slate-300 border-t-slate-500 rounded-full animate-spin" />
            Loading…
          </div>
        )}
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[11px] text-slate-600 uppercase tracking-wide border-b border-slate-100">
              <th scope="col" className="text-left py-2 font-medium">Timestamp</th>
              <th scope="col" className="text-left py-2 font-medium pl-4">Name</th>
              <th scope="col" className="text-left py-2 font-medium pl-4">Status</th>
              <th scope="col" className="text-right py-2 font-medium">Latency</th>
              <th scope="col" className="text-right py-2 font-medium">Tokens</th>
              <th scope="col" className="text-right py-2 font-medium">Cost</th>
              <th scope="col" className="text-left py-2 font-medium pl-4">User</th>
              <th scope="col" className="text-left py-2 font-medium pl-4">Trace id</th>
            </tr>
          </thead>
          <tbody>
            {display.map((r) => (
              <tr key={r.id} className="border-b border-slate-50 hover:bg-slate-50/40">
                <td className="py-2.5 text-slate-700 tabular-nums whitespace-nowrap">{r.timestamp}</td>
                <td className="py-2.5 pl-4 text-slate-700">{r.name}</td>
                <td className="py-2.5 pl-4 text-slate-600">{r.status}</td>
                <td className="py-2.5 text-right text-slate-600 tabular-nums whitespace-nowrap">{r.latency}</td>
                <td className="py-2.5 text-right text-slate-600 tabular-nums">{r.tokens}</td>
                <td className="py-2.5 text-right font-semibold text-slate-900 tabular-nums">{r.cost}</td>
                <td className="py-2.5 pl-4 text-slate-600 text-[13px] truncate max-w-[16rem]">{r.user}</td>
                <td className="py-2.5 pl-4 text-[11px] text-slate-600 font-mono whitespace-nowrap" title={r.id}>
                  {r.id.slice(0, 12)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pages > 1 && (
        <div className="flex items-center justify-between mt-4 pt-3 border-t border-slate-100">
          <div className="text-xs text-slate-600 tabular-nums">
            Page {page} of {pages} · {total.toLocaleString()} traces
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || loading}
              className="px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 text-xs font-medium hover:bg-slate-50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <button
              type="button"
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
              disabled={page >= pages || loading}
              className="px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 text-xs font-medium hover:bg-slate-50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
