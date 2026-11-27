// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ResponsiveContainer, ComposedChart, Area, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  PieChart, Pie, Cell,
} from 'recharts';
import { observabilityApi } from '../../../api/client';
import type { MetricsScope } from '../../../api/client';
import type { ScopeMetrics } from '../../../types';
import { useUser } from '../../../contexts/UserContext';
import { tooltipStyle } from '../../shared/chartTheme';
import { resolveTenantName } from '../tenantUi';
import { useAsync } from '../../shared/useAsync';
import { DataNotes, ObsEmptyCard } from '../agent-tabs/ObsEmptyCard';
import { COST_UNAVAILABLE_NOTE, costText, fmtUsd } from '../agent-tabs/agentObservability';
import { buildDashboardSeries, defaultDateRange } from './observabilityMetrics';

type Scope = MetricsScope;

const CARD = 'bg-white/80 backdrop-blur-sm rounded-xl border border-slate-200/60 p-5 shadow-sm';

const fmtInt = (n: number) => n.toLocaleString();

/** Fleet metrics for a scope and date range. Platform scope is offered to administrators only. */
export default function ObservabilityDashboard({ configured }: { configured: boolean }) {
  const { user } = useUser();
  const isAdmin = (user?.role_level ?? 0) >= 2;

  // Until the caller picks one, the scope follows their role, which loads after first render.
  const [scopeChoice, setScope] = useState<Scope | null>(null);
  const scope: Scope = isAdmin ? (scopeChoice ?? 'platform') : 'tenant';
  const [range, setRange] = useState(() => defaultDateRange());
  const { data: metrics, loading, error } = useAsync(
    () =>
      configured
        ? observabilityApi.getMetrics(scope, { dateFrom: range.dateFrom, dateTo: range.dateTo })
        : Promise.resolve<ScopeMetrics | null>(null),
    [configured, scope, range.dateFrom, range.dateTo],
    'Failed to load metrics',
  );

  const costAvailable = metrics?.cost_available !== false;
  const notes = [...(costAvailable ? [] : [COST_UNAVAILABLE_NOTE]), ...(metrics?.warnings ?? [])];
  const series = useMemo(() => buildDashboardSeries(metrics, range), [metrics, range]);

  if (!configured) {
    return (
      <ObsEmptyCard
        title="Observability not configured"
        body="No metrics source is connected in this environment yet. Once the assurance plane is collecting agent telemetry, traces, cost and token metrics render here."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex items-end gap-4">
          {isAdmin && (
            <div>
              <span id="obs-scope-label" className="block text-[11px] font-medium text-slate-500 uppercase tracking-wide mb-1">Scope</span>
              <div className="inline-flex bg-slate-100/80 rounded-lg p-0.5" role="group" aria-labelledby="obs-scope-label">
                {(['platform', 'tenant'] as Scope[]).map((s) => (
                  <button
                    key={s}
                    type="button"
                    aria-pressed={scope === s}
                    onClick={() => setScope(s)}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                      scope === s ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500 hover:text-slate-700'
                    }`}
                  >
                    {s === 'platform' ? 'Platform' : 'My tenants'}
                  </button>
                ))}
              </div>
            </div>
          )}
          <div>
            <label htmlFor="obs-from" className="block text-[11px] font-medium text-slate-500 uppercase tracking-wide mb-1">From</label>
            <input
              id="obs-from"
              type="date"
              value={range.dateFrom}
              max={range.dateTo}
              onChange={(e) => setRange((r) => ({ ...r, dateFrom: e.target.value }))}
              className="px-3 py-1.5 border border-slate-200 rounded-lg text-sm text-slate-700 bg-white"
            />
          </div>
          <div>
            <label htmlFor="obs-to" className="block text-[11px] font-medium text-slate-500 uppercase tracking-wide mb-1">To</label>
            <input
              id="obs-to"
              type="date"
              value={range.dateTo}
              min={range.dateFrom}
              onChange={(e) => setRange((r) => ({ ...r, dateTo: e.target.value }))}
              className="px-3 py-1.5 border border-slate-200 rounded-lg text-sm text-slate-700 bg-white"
            />
          </div>
        </div>
        {loading && (
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span className="w-3.5 h-3.5 border-2 border-slate-300 border-t-slate-500 rounded-full animate-spin" />
            Loading metrics…
          </div>
        )}
      </div>

      {error ? (
        <ObsEmptyCard title="Couldn't load metrics" body={error} tone="amber" />
      ) : series.isEmpty && !loading ? (
        <ObsEmptyCard
          title="No traces in this window"
          body="No agent activity was recorded for the selected scope and date range. Try widening the date range."
        />
      ) : (
        <>
          <DataNotes notes={notes} />
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <Kpi label="Total Traces" value={fmtInt(series.totals.traces)} sub="agent invocations" color="#3b82f6" />
            <Kpi label="Total Cost" value={costText(series.totals.cost, costAvailable)} sub="model spend (USD)" color="#f59e0b" />
            <Kpi label="Total Tokens" value={fmtInt(series.totals.tokens)} sub="input + output" color="#6366f1" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-[2fr_1fr] gap-4">
            <div className={CARD}>
              <div className="text-sm font-semibold text-slate-900 mb-3">Cost &amp; Traces</div>
              {series.timeseries.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <ComposedChart data={series.timeseries}>
                    <defs>
                      <linearGradient id="obsCostGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.3} />
                        <stop offset="100%" stopColor="#f59e0b" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                    <XAxis dataKey="date" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                    <YAxis yAxisId="cost" tick={{ fill: '#94a3b8', fontSize: 10 }} unit="$" />
                    <YAxis yAxisId="traces" orientation="right" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                    <Tooltip
                      contentStyle={tooltipStyle}
                      formatter={(v, name) => (name === 'Cost' ? fmtUsd(Number(v)) : fmtInt(Number(v)))}
                    />
                    <Area yAxisId="cost" type="monotone" dataKey="cost" name="Cost" stroke="#f59e0b" fill="url(#obsCostGrad)" strokeWidth={2} />
                    <Line yAxisId="traces" type="monotone" dataKey="traces" name="Traces" stroke="#3b82f6" strokeWidth={2} dot={false} />
                    <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '6px' }} />
                  </ComposedChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[220px] flex items-center justify-center text-sm text-slate-400">No daily breakdown for this range.</div>
              )}
            </div>

            <div className={CARD}>
              <div className="text-sm font-semibold text-slate-900 mb-3">{costAvailable ? 'Cost by Model' : 'Tokens by Model'}</div>
              {series.byModel.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart>
                      <Pie data={series.byModel} dataKey={costAvailable ? 'cost' : 'tokens'} nameKey="model" cx="50%" cy="50%" outerRadius={70} innerRadius={42} paddingAngle={2}>
                        {series.byModel.map((m) => <Cell key={m.model} fill={m.color} />)}
                      </Pie>
                      <Tooltip contentStyle={tooltipStyle} formatter={(v) => (costAvailable ? fmtUsd(Number(v)) : fmtInt(Number(v)))} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="grid grid-cols-1 gap-y-1 text-[11px] mt-2">
                    {series.byModel.map((m) => (
                      <div key={m.model} className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: m.color }} />
                        <span className="text-slate-700 truncate">{m.model}</span>
                        <span className="text-slate-400 ml-auto tabular-nums">{costAvailable ? fmtUsd(m.cost) : fmtInt(m.tokens)}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="h-[180px] flex items-center justify-center text-sm text-slate-400">No model breakdown yet.</div>
              )}
            </div>
          </div>

          <div className={CARD}>
            <div className="text-sm font-semibold text-slate-900 mb-3">By Agent</div>
            {series.byAgent.length > 0 ? (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[11px] text-slate-400 uppercase tracking-wide border-b border-slate-100">
                    <th scope="col" className="text-left py-2 font-medium">Agent</th>
                    <th scope="col" className="text-left py-2 font-medium pl-4">Tenant</th>
                    <th scope="col" className="text-right py-2 font-medium">Traces</th>
                    <th scope="col" className="text-right py-2 font-medium">Cost</th>
                    <th scope="col" className="text-right py-2 font-medium">Tokens</th>
                  </tr>
                </thead>
                <tbody>
                  {series.byAgent.map((a) => {
                    const tenantName = resolveTenantName(a.tenant_id, user?.tenants);
                    return (
                      <tr key={a.agent_id} className="border-b border-slate-50 hover:bg-slate-50/40">
                        <td className="py-2.5">
                          <Link to={`/agents/${a.agent_id}`} className="text-slate-700 font-medium hover:text-blue-600 transition-colors">
                            {a.agent_name}
                          </Link>
                        </td>
                        <td className="py-2.5 pl-4 text-slate-500 text-[13px]">{tenantName ?? a.tenant_id ?? '—'}</td>
                        <td className="py-2.5 text-right text-slate-700 tabular-nums">{fmtInt(a.traces)}</td>
                        <td className="py-2.5 text-right font-semibold text-slate-900 tabular-nums">{costText(a.cost, costAvailable)}</td>
                        <td className="py-2.5 text-right text-slate-500 tabular-nums">{fmtInt(a.tokens)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <div className="py-8 text-center text-sm text-slate-400">No agents with traces in this scope.</div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function Kpi({ label, value, sub, color }: { label: string; value: string; sub: string; color: string }) {
  return (
    <div className={CARD}>
      <div className="text-[11px] font-medium text-slate-500 uppercase tracking-wide">{label}</div>
      <div className="text-2xl font-semibold mt-1 tabular-nums" style={{ color }}>{value}</div>
      <div className="text-[11px] text-slate-400 mt-0.5">{sub}</div>
    </div>
  );
}

