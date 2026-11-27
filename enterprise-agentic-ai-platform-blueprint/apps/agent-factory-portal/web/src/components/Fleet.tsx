// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { agentsApi, fleetApi, mcpServersApi } from '../api/client';
import type { Agent } from '../api/client';
import { useUser } from '../contexts/UserContext';
import { cellStateView, fleetTotals, sortCells } from './fleetHealth';
import { lifecycleBadge } from './governance/agentUi';
import { resolveTenantName } from './governance/tenantUi';
import { Badge, CARD, ErrorCard, Loading, Page, PageHeader, TABLE_HEAD, TD, TH, formatDate } from './shared/ui';
import { useAsync } from './shared/useAsync';

const RECENT_AGENT_COUNT = 5;

function StatCard({ label, value, to, tone }: { label: string; value: string; to?: string; tone?: 'attention' | 'critical' }) {
  const valueCls = tone === 'critical' ? 'text-red-600' : tone === 'attention' ? 'text-amber-600' : 'text-slate-900';
  const body = (
    <div className={`${CARD} p-5 h-full ${to ? 'transition-shadow hover:shadow-md' : ''}`}>
      <div className={`text-3xl font-semibold tabular-nums ${valueCls}`}>{value}</div>
      <div className="text-sm font-medium text-slate-700 mt-1">{label}</div>
    </div>
  );
  return to ? (
    <Link to={to} className="block focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded-xl">
      {body}
    </Link>
  ) : (
    body
  );
}

/** Home screen: fleet counts, the health of every Workstream cell, and recently added agents. */
export default function Fleet() {
  const { user } = useUser();
  const agents = useAsync(() => agentsApi.list(), [], 'Failed to load agents.');
  const gateways = useAsync(() => mcpServersApi.list(), [], 'Failed to load tool gateways.');
  const health = useAsync(() => fleetApi.health(), [], 'Failed to load fleet health.');

  const agentNames = useMemo(() => {
    const names = new Map<string, string>();
    for (const a of agents.data ?? []) names.set(a.id, a.name);
    return names;
  }, [agents.data]);

  const recentAgents = useMemo<Agent[]>(
    () => [...(agents.data ?? [])].sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, RECENT_AGENT_COUNT),
    [agents.data],
  );

  const totals = fleetTotals(health.data);
  const cells = useMemo(() => sortCells(health.data?.cells ?? []), [health.data]);
  const count = (state: { data: unknown[] | null; loading: boolean; error: string | null }) =>
    state.loading ? '…' : state.error ? '—' : String(state.data?.length ?? 0);
  const healthCount = (n: number) => (health.loading ? '…' : health.error ? '—' : String(n));

  return (
    <Page>
      <PageHeader
        title="Fleet"
        subtitle="Every agent the factory operates, the tool gateways it calls through, and the health of each Workstream cell. This view is read-only: cells change only through their pipeline."
      />

      <section aria-label="Fleet counts" className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
        <StatCard label="Agents" value={count(agents)} to="/agents" />
        <StatCard label="Tool gateways" value={count(gateways)} to="/tool-gateways" />
        <StatCard label="Healthy cells" value={healthCount(totals.healthy)} />
        <StatCard label="Need attention" value={healthCount(totals.needs_attention)} tone={totals.needs_attention > 0 ? 'attention' : undefined} />
        <StatCard label="Critical" value={healthCount(totals.critical)} tone={totals.critical > 0 ? 'critical' : undefined} />
        <StatCard label="No data" value={healthCount(totals.no_data)} tone={totals.no_data > 0 ? 'attention' : undefined} />
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <section className="lg:col-span-2" aria-labelledby="fleet-health-heading">
          <div className="flex items-baseline justify-between mb-3">
            <h2 id="fleet-health-heading" className="text-base font-semibold text-slate-900">Fleet health</h2>
            {health.data && <span className="text-xs text-slate-400">Checked {formatDate(health.data.checked_at)}</span>}
          </div>
          {health.loading ? (
            <Loading label="Loading fleet health…" />
          ) : health.error ? (
            <ErrorCard title="Couldn’t load fleet health" message={health.error} onRetry={health.reload} />
          ) : cells.length === 0 ? (
            <div className={`${CARD} p-6 text-sm text-slate-500`}>No Workstream cells are reporting yet.</div>
          ) : (
            <div className={`${CARD} overflow-x-auto`}>
              <table className="w-full text-sm">
                <thead className={TABLE_HEAD}>
                  <tr>
                    <th scope="col" className={TH}>Agent</th>
                    <th scope="col" className={TH}>Tenant</th>
                    <th scope="col" className={TH}>Environment</th>
                    <th scope="col" className={TH}>Account · Region</th>
                    <th scope="col" className={TH}>State</th>
                    <th scope="col" className={`${TH} text-right`}>Alarms</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {cells.map((cell) => {
                    const view = cellStateView(cell.state);
                    return (
                      <tr key={`${cell.tenant_id}/${cell.agent_id}/${cell.environment}`}>
                        <td className={TD}>
                          {cell.agent_ref ? (
                            <Link to={`/agents/${encodeURIComponent(cell.agent_ref)}`} className="font-medium text-blue-700 hover:underline">
                              {agentNames.get(cell.agent_ref) ?? cell.agent_id}
                            </Link>
                          ) : (
                            <span className="font-medium text-slate-700">{cell.agent_id}</span>
                          )}
                        </td>
                        <td className={`${TD} text-slate-600`}>{resolveTenantName(cell.tenant_id, user?.tenants) ?? cell.tenant_id}</td>
                        <td className={`${TD} text-slate-600`}>{cell.environment}</td>
                        <td className={`${TD} text-slate-600`}>{cell.account_alias} · {cell.region}</td>
                        <td className={TD}>
                          <Badge cls={view.cls} label={view.label} title={cell.detail || (cell.reachable ? undefined : 'Telemetry for this cell could not be read.')} />
                        </td>
                        <td className={`${TD} text-right tabular-nums text-slate-700`}>{cell.reachable ? cell.alarms_in_alarm : '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section aria-labelledby="recent-agents-heading">
          <h2 id="recent-agents-heading" className="text-base font-semibold text-slate-900 mb-3">Recently added agents</h2>
          <div className={`${CARD} p-5`}>
            {agents.loading ? (
              <Loading label="Loading agents…" />
            ) : agents.error ? (
              <p className="text-sm text-slate-500">Agents couldn’t be loaded. {agents.error}</p>
            ) : recentAgents.length === 0 ? (
              <p className="text-sm text-slate-500">
                No agents yet. Agents appear here once a Workstream pipeline has deployed one from its descriptor.
              </p>
            ) : (
              <ul className="space-y-2.5">
                {recentAgents.map((a) => {
                  const badge = lifecycleBadge(a.lifecycle_state);
                  return (
                    <li key={a.id} className="flex items-center justify-between gap-2.5 text-sm">
                      <Link to={`/agents/${encodeURIComponent(a.id)}`} className="truncate text-slate-700 hover:text-blue-700" title={a.name}>
                        {a.name}
                      </Link>
                      <Badge cls={`${badge.cls} shrink-0`} label={badge.label} />
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </section>
      </div>
    </Page>
  );
}
