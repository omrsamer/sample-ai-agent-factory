// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { mcpServersApi } from '../../api/client';
import type { LifecycleState, McpServerKind } from '../../api/client';
import { useUser } from '../../contexts/UserContext';
import { AgentAvatar, LIFECYCLE_OPTIONS, lifecycleBadge, emailAlias, kindBadge, tenantBadge } from './agentUi';
import { enforcementLabel } from './cedarPosture';
import { mcpEndpoint } from './mcpServerDetailTabs';
import { resolveTenantName } from './tenantUi';
import { Badge, CARD, ErrorCard, Page, PageHeader, TABLE_HEAD, TD, TH } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

const KIND_OPTIONS: { value: McpServerKind; label: string }[] = [
  { value: 'gateway', label: 'Gateway' },
  { value: 'runtime', label: 'Runtime' },
  { value: 'standard', label: 'Standard' },
];

const INPUT = 'w-full px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/40';

/** Every tool gateway agents can call through. Read-only. */
export default function ToolGateways() {
  const { user } = useUser();
  const [filterLifecycle, setFilterLifecycle] = useState<'all' | LifecycleState>('all');
  const [filterKind, setFilterKind] = useState<'all' | McpServerKind>('all');
  const [search, setSearch] = useState('');
  const { data, loading, error, reload } = useAsync(
    () => mcpServersApi.list(filterLifecycle === 'all' ? undefined : { lifecycle_state: filterLifecycle }),
    [filterLifecycle],
    'Failed to load tool gateways.',
  );

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (data ?? []).filter((m) => {
      if (q && !`${m.name} ${m.owner_email ?? ''}`.toLowerCase().includes(q)) return false;
      if (filterKind !== 'all' && m.kind !== filterKind) return false;
      return true;
    });
  }, [data, search, filterKind]);

  const filtered = search.trim() !== '' || filterKind !== 'all' || filterLifecycle !== 'all';

  return (
    <Page>
      <PageHeader
        title="Tool gateways"
        subtitle="The gateways agents call tools through. Each is governed once, with its own tools, Cedar policies and subscribed agents. The default gateway authorises callers with AWS IAM."
      />

      <div className={`${CARD} p-2.5 mb-3`}>
        <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
          <div className="md:col-span-6">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by name or owner…"
              aria-label="Search tool gateways by name or owner"
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
              aria-label="Filter by kind"
              className={INPUT}
              value={filterKind}
              onChange={(e) => setFilterKind(e.target.value as 'all' | McpServerKind)}
            >
              <option value="all">All kinds</option>
              {KIND_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {error ? (
        <ErrorCard title="Couldn’t load tool gateways" message={error} onRetry={reload} />
      ) : (
        <div className={`${CARD} overflow-x-auto`}>
          <table className="w-full text-sm">
            <thead className={TABLE_HEAD}>
              <tr>
                <th scope="col" className={TH}>Tool gateway</th>
                <th scope="col" className={TH}>Kind</th>
                <th scope="col" className={TH}>Tenant</th>
                <th scope="col" className={TH}>Owner</th>
                <th scope="col" className={`${TH} text-right`}>Tools</th>
                <th scope="col" className={TH}>Cedar</th>
                <th scope="col" className={TH}>Lifecycle</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-600 text-sm" role="status">Loading tool gateways…</td>
                </tr>
              )}
              {!loading && rows.map((m) => {
                const kind = kindBadge(m.kind);
                const lifecycle = lifecycleBadge(m.lifecycle_state);
                const tenant = m.shared
                  ? { cls: 'bg-violet-50 text-violet-700', label: 'Shared' }
                  : tenantBadge(resolveTenantName(m.tenant_id, user?.tenants) ?? m.tenant_id);
                return (
                  <tr key={m.id} className="hover:bg-blue-50/40 transition-colors">
                    <td className={TD}>
                      <div className="flex items-center gap-2.5">
                        <AgentAvatar name={m.name} size="sm" />
                        <div className="min-w-0 leading-tight">
                          <Link to={`/tool-gateways/${encodeURIComponent(m.id)}`} className="block font-medium text-blue-700 hover:underline truncate">
                            {m.name}
                          </Link>
                          <span className="block text-xs text-slate-600 truncate">{mcpEndpoint(m)?.url ?? 'No endpoint recorded'}</span>
                        </div>
                      </div>
                    </td>
                    <td className={TD}><Badge cls={kind.cls} label={kind.label} /></td>
                    <td className={TD}><Badge cls={tenant.cls} label={tenant.label} title={m.tenant_id ?? undefined} /></td>
                    <td className={`${TD} text-slate-600`} title={m.owner_email ?? undefined}>{emailAlias(m.owner_email)}</td>
                    <td className={`${TD} text-right tabular-nums text-slate-700`}>{m.available_tools?.length ?? 0}</td>
                    <td className={`${TD} text-slate-600`}>{m.kind === 'gateway' ? enforcementLabel(m.cedar_enforcement_mode) : '—'}</td>
                    <td className={TD}><Badge cls={lifecycle.cls} label={lifecycle.label} /></td>
                  </tr>
                );
              })}
              {!loading && rows.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-600 text-sm">
                    {filtered ? 'No tool gateways match the current filters.' : 'No tool gateways in the registry yet.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}
