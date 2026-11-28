// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { mcpServersApi } from '../../api/client';
import { useUser } from '../../contexts/UserContext';
import { AgentAvatar, BreakableName, tenantBadge } from './agentUi';
import {
  NOT_READABLE,
  READER_FILTER_OPTIONS,
  gatewayAccount,
  gatewayChip,
  gatewayLifecycle,
  gatewayRead,
  matchesGateway,
  policyCell,
  toolsCell,
  unreadNote,
  type ReaderFilter,
} from './gatewayView';
import { mcpEndpoint } from './mcpServerDetailTabs';
import { resolveTenantName } from './tenantUi';
import { Badge, CARD, ErrorCard, NOT_SET, Page, PageHeader, TABLE_HEAD, TD, TH } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

const INPUT = 'w-full px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/40';

/** Every tool gateway agents can call through. Read-only. */
export default function ToolGateways() {
  const { user } = useUser();
  // Whether a reader read the gateway: one that only the organization registry detected is
  // listed with its account and nothing of its tools or policy.
  const [filterReader, setFilterReader] = useState<ReaderFilter>('all');
  const [search, setSearch] = useState('');
  const { data, loading, error, reload } = useAsync(() => mcpServersApi.list(), [], 'Failed to load tool gateways.');

  const rows = useMemo(() => (data ?? []).filter((m) => matchesGateway(m, search, filterReader)), [data, search, filterReader]);
  const note = useMemo(() => unreadNote((data ?? []).filter((m) => !gatewayRead(m)).length), [data]);

  const filtered = search.trim() !== '' || filterReader !== 'all';

  return (
    <Page>
      <PageHeader
        title="Tool gateways"
        subtitle="The gateways agents call tools through. Each is governed once, with its own tools, Cedar policies and subscribed agents. The default gateway authorises callers with AWS IAM."
      />

      {note && <p className="text-sm text-slate-700 mb-3">{note}</p>}

      <div className={`${CARD} p-2.5 mb-3`}>
        <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
          <div className="md:col-span-8">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by name or account…"
              aria-label="Search tool gateways by name or account"
              className={INPUT}
            />
          </div>
          <div className="md:col-span-4">
            <select
              aria-label="Filter by whether a reader read the gateway"
              className={INPUT}
              value={filterReader}
              onChange={(e) => setFilterReader(e.target.value as ReaderFilter)}
            >
              {READER_FILTER_OPTIONS.map((o) => (
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
                <th scope="col" className={TH}>Tenant</th>
                <th scope="col" className={TH}>Account</th>
                <th scope="col" className={`${TH} text-right`}>Tools</th>
                <th scope="col" className={TH}>Policy</th>
                <th scope="col" className={TH}>State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-600 text-sm" role="status">Loading tool gateways…</td>
                </tr>
              )}
              {!loading && rows.map((m) => {
                const read = gatewayRead(m);
                const chip = gatewayChip(m);
                const state = gatewayLifecycle(m);
                const account = gatewayAccount(m);
                const tenant = m.shared
                  ? { cls: 'bg-violet-50 text-violet-700', label: 'Shared' }
                  : tenantBadge(resolveTenantName(m.tenant_id, user?.tenants) ?? m.tenant_id);
                return (
                  <tr key={m.id} className="hover:bg-blue-50/40 transition-colors align-top">
                    <td className={`${TD} min-w-[12rem] max-w-[22rem]`}>
                      <div className="flex items-start gap-2.5">
                        <AgentAvatar name={m.name} size="sm" />
                        <div className="min-w-0 leading-tight">
                          <Link to={`/tool-gateways/${encodeURIComponent(m.id)}`} className="font-medium text-blue-700 hover:underline">
                            <BreakableName name={m.name} />
                          </Link>
                          {read ? (
                            <span className="block text-xs text-slate-600 truncate">{mcpEndpoint(m)?.url ?? 'No endpoint recorded'}</span>
                          ) : (
                            chip && (
                              <span className="block mt-1">
                                <Badge cls={chip.cls} label={chip.label} title={chip.hint} />
                              </span>
                            )
                          )}
                        </div>
                      </div>
                    </td>
                    {/* The tenant of a gateway no reader read is not known: that is not "None". */}
                    <td className={`${TD} whitespace-nowrap`}>
                      {read ? <Badge cls={tenant.cls} label={tenant.label} title={m.tenant_id ?? undefined} /> : <span className="text-slate-600">{NOT_READABLE}</span>}
                    </td>
                    <td className={`${TD} text-slate-700 whitespace-nowrap`}>
                      {account || <span className="text-slate-600">{NOT_SET}</span>}
                      {m.region && <span className="block text-xs text-slate-600">{m.region}</span>}
                    </td>
                    <td className={`${TD} text-right tabular-nums text-slate-700 whitespace-nowrap`}>{toolsCell(m)}</td>
                    <td className={`${TD} text-slate-700`}>{policyCell(m)}</td>
                    <td className={`${TD} whitespace-nowrap`}><Badge cls={state.cls} label={state.label} /></td>
                  </tr>
                );
              })}
              {!loading && rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-600 text-sm">
                    {filtered ? 'No tool gateways match the current filters.' : 'No tool gateway was read or detected.'}
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
