// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { agentsApi } from '../../api/client';
import type { LifecycleState } from '../../api/client';
import { useUser } from '../../contexts/UserContext';
import { AgentAvatar, LIFECYCLE_OPTIONS, lifecycleBadge, originBadge, emailAlias, tenantBadge } from './agentUi';
import { resolveTenantName } from './tenantUi';
import { platformLabelOr } from './platformLabels';
import { Badge, CARD, ErrorCard, Page, PageHeader, TABLE_HEAD, TD, TH } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

const INPUT = 'w-full px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/40';

/** Every agent in the registry, with client-side search and filters. Read-only. */
export function AgentsTable({ linkBase = '/agents' }: { linkBase?: string }) {
  const { user } = useUser();
  const [filterLifecycle, setFilterLifecycle] = useState<'all' | LifecycleState>('all');
  const [search, setSearch] = useState('');
  const [filterBusinessUnit, setFilterBusinessUnit] = useState('all');
  const { data, loading, error, reload } = useAsync(
    () => agentsApi.list(filterLifecycle === 'all' ? undefined : { lifecycle_state: filterLifecycle }),
    [filterLifecycle],
    'Failed to load agents.',
  );
  const agents = useMemo(() => data ?? [], [data]);

  const businessUnits = useMemo(() => {
    const set = new Set<string>();
    for (const a of agents) if (a.business_unit) set.add(a.business_unit);
    return Array.from(set).sort((x, y) => x.localeCompare(y));
  }, [agents]);

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return agents.filter((a) => {
      if (q && !`${a.name} ${a.sponsor_email ?? ''}`.toLowerCase().includes(q)) return false;
      if (filterBusinessUnit !== 'all' && a.business_unit !== filterBusinessUnit) return false;
      return true;
    });
  }, [agents, search, filterBusinessUnit]);

  const filtered = search.trim() !== '' || filterBusinessUnit !== 'all' || filterLifecycle !== 'all';

  return (
    <>
      <div className={`${CARD} p-2.5 mb-3`}>
        <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
          <div className="md:col-span-6">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by name or owner…"
              aria-label="Search agents by name or owner"
              className={INPUT}
            />
          </div>
          <div className="md:col-span-3">
            <select
              aria-label="Filter by lifecycle state"
              className={INPUT}
              value={filterLifecycle}
              onChange={(e) => setFilterLifecycle(e.target.value as 'all' | LifecycleState)}
            >
              <option value="all">All lifecycle states</option>
              {LIFECYCLE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div className="md:col-span-3">
            <select
              aria-label="Filter by business unit"
              className={INPUT}
              value={filterBusinessUnit}
              onChange={(e) => setFilterBusinessUnit(e.target.value)}
            >
              <option value="all">All business units</option>
              {businessUnits.map((bu) => (
                <option key={bu} value={bu}>{bu}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {error ? (
        <ErrorCard title="Couldn’t load agents" message={error} onRetry={reload} />
      ) : (
        <div className={`${CARD} overflow-x-auto`}>
          <table className="w-full text-sm">
            <thead className={TABLE_HEAD}>
              <tr>
                <th scope="col" className={TH}>Agent</th>
                <th scope="col" className={TH}>Tenant</th>
                <th scope="col" className={TH}>Business unit</th>
                <th scope="col" className={TH}>Owner</th>
                <th scope="col" className={TH}>Origin</th>
                <th scope="col" className={TH}>Lifecycle</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-400 text-sm" role="status">Loading agents…</td>
                </tr>
              )}
              {!loading && rows.map((a) => {
                const origin = originBadge(a.origin);
                const lifecycle = lifecycleBadge(a.lifecycle_state);
                const tenant = tenantBadge(resolveTenantName(a.tenant_id, user?.tenants) ?? a.tenant_id);
                return (
                  <tr key={a.id} className="hover:bg-blue-50/40 transition-colors">
                    <td className={TD}>
                      <div className="flex items-center gap-2.5">
                        <AgentAvatar name={a.name} size="sm" />
                        <div className="min-w-0 leading-tight">
                          <Link to={`${linkBase}/${encodeURIComponent(a.id)}`} className="block font-medium text-blue-700 hover:underline truncate">
                            {a.name}
                          </Link>
                          <span className="block text-xs text-slate-500 truncate">{platformLabelOr(a.platform, 'Platform not recorded')}</span>
                        </div>
                      </div>
                    </td>
                    <td className={TD}><Badge cls={tenant.cls} label={tenant.label} title={a.tenant_id ?? undefined} /></td>
                    <td className={`${TD} text-slate-600`}>{a.business_unit ?? '—'}</td>
                    <td className={`${TD} text-slate-600`} title={a.sponsor_email ?? undefined}>{emailAlias(a.sponsor_email)}</td>
                    <td className={TD}><Badge cls={origin.cls} label={origin.label} /></td>
                    <td className={TD}><Badge cls={lifecycle.cls} label={lifecycle.label} /></td>
                  </tr>
                );
              })}
              {!loading && rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-400 text-sm">
                    {filtered ? 'No agents match the current filters.' : 'No agents in the registry yet.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

export default function AgentsList() {
  return (
    <Page>
      <PageHeader
        title="Agents"
        subtitle="Every agent the factory operates. Agents are created and changed through their descriptor and pipeline, not from this portal."
      />
      <AgentsTable />
    </Page>
  );
}
