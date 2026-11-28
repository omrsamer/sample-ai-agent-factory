// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { agentsApi } from '../../api/client';
import { safeStorage } from '../../api/authRetry';
import type { ExportFormat } from '../../api/client';
import { useUser } from '../../contexts/UserContext';
import { AgentAvatar, BreakableName, LIFECYCLE_OPTIONS, lifecycleBadge, tenantBadge } from './agentUi';
import { AgentChips, AgentRisk, ContainedBadge, InventoryStateBadge } from './InventoryBadges';
import {
  AWAITING_APPROVAL,
  FLAG_FILTER_OPTIONS,
  INVENTORY_STATE_OPTIONS,
  RISK_LEVELS,
  accountLabel,
  accountOptions,
  exportFilename,
  filtersFromSearch,
  hasFilters,
  hasRegistration,
  inTenants,
  matchesFilters,
  ownTenants,
  riskTag,
  searchFromFilters,
  sponsorOf,
  type InventoryFilters,
} from './inventory';
import { resolveTenantName } from './tenantUi';
import { platformLabelOr } from './platformLabels';
import { saveFile } from '../shared/download';
import { Badge, CARD, ErrorCard, Page, PageHeader, TABLE_HEAD, errorMessage } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

const INPUT = 'w-full px-3 py-1.5 text-sm rounded-lg border border-slate-400 bg-white';
const BTN = 'px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-800 text-sm font-medium hover:bg-slate-50 disabled:opacity-50';
// Seven columns need the room: this table's cells are a little narrower than the shared ones.
const HEAD_CELL = 'text-left font-medium px-3 py-2';
const CELL = 'px-3 py-2';
/** Whether the list is narrowed to the caller's own tenants. Kept for the browser session. */
const MY_TENANTS_KEY = 'afp.agents.myTenants';

// Below the desktop width the tenant and the lifecycle have no column of their own: the tenant
// is written under the account and the lifecycle under the state, so nothing wraps into slivers.
const WIDE_ONLY = 'hidden xl:table-cell';

/** Export of the whole inventory. The file is fetched with the bearer token, then saved. */
function ExportControl() {
  const [busy, setBusy] = useState<ExportFormat | null>(null);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);

  const run = async (format: ExportFormat) => {
    setBusy(format);
    setMessage(null);
    try {
      const file = await agentsApi.exportInventory(format);
      const filename = exportFilename(file.contentDisposition, format);
      saveFile(file.blob, filename);
      setMessage({ text: `Saved ${filename}.`, error: false });
    } catch (err) {
      setMessage({ text: `The export failed. ${errorMessage(err, '')}`.trim(), error: true });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Export the inventory">
      <span className="text-sm text-slate-700">Export</span>
      <button type="button" className={BTN} disabled={busy !== null} onClick={() => void run('csv')}>
        {busy === 'csv' ? 'Exporting…' : 'CSV'}
      </button>
      <button type="button" className={BTN} disabled={busy !== null} onClick={() => void run('json')}>
        {busy === 'json' ? 'Exporting…' : 'JSON'}
      </button>
      <span role="status" className={`text-xs ${message?.error ? 'text-red-700' : 'text-slate-600'}`}>
        {message?.text}
      </span>
    </div>
  );
}

/**
 * Every agent the factory knows about, registered or only detected, with its inventory state,
 * risk, account and lifecycle. Search and filters run in the browser; the filters are kept in
 * the address so a count on the fleet page can link straight to the agents it counts.
 */
export function AgentsTable({ linkBase = '/agents' }: { linkBase?: string }) {
  const { user } = useUser();
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = filtersFromSearch(searchParams);
  const [search, setSearch] = useState('');
  // Offered only to a caller who acts for some tenants and not for all of them.
  const mine = ownTenants(user);
  const [onlyMine, setOnlyMine] = useState(() => safeStorage.read(MY_TENANTS_KEY) === '1');
  const narrowed = !!mine && onlyMine;
  // The list is rebuilt on every render; its content is what the rows depend on.
  const mineKey = (mine ?? []).join('|');
  const { data, loading, error, reload } = useAsync(() => agentsApi.list(), [], 'Failed to load agents.');
  const agents = useMemo(() => data ?? [], [data]);
  const accounts = useMemo(() => accountOptions(agents), [agents]);

  const setFilter = (key: keyof InventoryFilters, value: string) =>
    setSearchParams(searchFromFilters({ ...filters, [key]: value }), { replace: true });

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return agents.filter((a) => {
      if (narrowed && mine && !inTenants(a, mine)) return false;
      if (q && !`${a.name} ${a.governance?.owner_group ?? ''} ${sponsorOf(a)}`.toLowerCase().includes(q)) return false;
      return matchesFilters(a, filters);
    });
    // The filters object and the tenant list are rebuilt on every render; their values are the real inputs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents, search, narrowed, mineKey, filters.flag, filters.risk, filters.state, filters.lifecycle, filters.account]);

  const filtered = search.trim() !== '' || hasFilters(filters);

  return (
    <>
      <div className={`${CARD} p-2.5 mb-3`}>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name, owner group or sponsor…"
            aria-label="Search agents by name, owner group or sponsor"
            className={INPUT}
          />
          <select aria-label="Filter by inventory state" className={INPUT} value={filters.state} onChange={(e) => setFilter('state', e.target.value)}>
            <option value="">All inventory states</option>
            {INVENTORY_STATE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <select aria-label="Filter by account" className={INPUT} value={filters.account} onChange={(e) => setFilter('account', e.target.value)}>
            <option value="">All accounts</option>
            {/* An account named in the address stays selectable even when no agent is in it. */}
            {[...new Set([...accounts, ...(filters.account ? [filters.account] : [])])].map((account) => (
              <option key={account} value={account}>{account}</option>
            ))}
          </select>
          <select aria-label="Filter by risk" className={INPUT} value={filters.risk} onChange={(e) => setFilter('risk', e.target.value)}>
            <option value="">All risk levels</option>
            {RISK_LEVELS.map((level) => (
              <option key={level} value={level}>{riskTag(level).label}</option>
            ))}
            <option value="none">Risk not assessed</option>
          </select>
          <select aria-label="Filter by flag" className={INPUT} value={filters.flag} onChange={(e) => setFilter('flag', e.target.value)}>
            <option value="">All flags</option>
            {FLAG_FILTER_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <select aria-label="Filter by lifecycle state" className={INPUT} value={filters.lifecycle} onChange={(e) => setFilter('lifecycle', e.target.value)}>
            <option value="">All lifecycle states</option>
            <option value={AWAITING_APPROVAL}>Registered, not approved yet</option>
            {LIFECYCLE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 mt-2.5 px-1">
          <p className="text-xs text-slate-600" role="status">
            {loading ? 'Loading…' : `${rows.length} of ${agents.length} agents shown`}
            {filtered && !loading && (
              <>
                {' · '}
                <button
                  type="button"
                  className="text-blue-700 underline"
                  onClick={() => {
                    setSearch('');
                    setSearchParams({}, { replace: true });
                  }}
                >
                  Clear filters
                </button>
              </>
            )}
          </p>
          {mine && (
            <label className="inline-flex items-center gap-2 text-sm text-slate-800" title={`Only agents of: ${mine.join(', ')}`}>
              <input
                type="checkbox"
                className="h-4 w-4"
                checked={onlyMine}
                onChange={(e) => {
                  setOnlyMine(e.target.checked);
                  if (e.target.checked) safeStorage.write(MY_TENANTS_KEY, '1');
                  else safeStorage.remove(MY_TENANTS_KEY);
                }}
              />
              My tenants
              <span className="sr-only">: show only the agents of {mine.join(', ')}</span>
            </label>
          )}
          <ExportControl />
        </div>
      </div>

      {error ? (
        <ErrorCard title="Couldn’t load agents" message={error} onRetry={reload} />
      ) : (
        <div className={`${CARD} overflow-x-auto`}>
          <table className="w-full text-sm">
            <thead className={TABLE_HEAD}>
              <tr>
                <th scope="col" className={HEAD_CELL}>Agent</th>
                <th scope="col" className={HEAD_CELL}>State</th>
                <th scope="col" className={HEAD_CELL}>Risk</th>
                <th scope="col" className={HEAD_CELL}>Flags</th>
                <th scope="col" className={`${HEAD_CELL} ${WIDE_ONLY}`}>Tenant</th>
                <th scope="col" className={HEAD_CELL}>Account</th>
                <th scope="col" className={`${HEAD_CELL} ${WIDE_ONLY}`}>Lifecycle</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-600 text-sm" role="status">Loading agents…</td>
                </tr>
              )}
              {!loading && rows.map((a) => {
                const lifecycle = lifecycleBadge(a.lifecycle_state);
                const tenant = tenantBadge(resolveTenantName(a.tenant_id, user?.tenants) ?? a.tenant_id);
                const account = accountLabel(a);
                const registered = hasRegistration(a);
                return (
                  <tr key={a.id} className="hover:bg-blue-50/40 align-top">
                    <td className={CELL}>
                      {/* Wide enough for a name to wrap at its separators, never inside a word. */}
                      <div className="flex items-start gap-2.5 min-w-[12rem] xl:min-w-[16.25rem] max-w-[22rem]">
                        <AgentAvatar name={a.name} size="sm" />
                        <div className="min-w-0 leading-tight">
                          <span className="flex flex-wrap items-center gap-1.5">
                            <Link to={`${linkBase}/${encodeURIComponent(a.id)}`} className="font-medium text-blue-700 hover:underline">
                              <BreakableName name={a.name} />
                            </Link>
                            <ContainedBadge agent={a} />
                          </span>
                          <span className="block text-xs text-slate-600">{platformLabelOr(a.platform, 'Platform not recorded')}</span>
                        </div>
                      </div>
                    </td>
                    {/* Two short labels, each kept on one line: a wrapped pill reads as two. */}
                    <td className={`${CELL} whitespace-nowrap`}>
                      <InventoryStateBadge state={a.inventory_state} />
                      {registered && (
                        <span className="block mt-1 xl:hidden">
                          <Badge cls={lifecycle.cls} label={lifecycle.label} />
                        </span>
                      )}
                    </td>
                    <td className={`${CELL} whitespace-nowrap`}><AgentRisk agent={a} inWords /></td>
                    <td className={CELL}><AgentChips agent={a} /></td>
                    <td className={`${CELL} ${WIDE_ONLY} whitespace-nowrap`}><Badge cls={tenant.cls} label={tenant.label} title={a.tenant_id ?? undefined} /></td>
                    <td className={`${CELL} text-slate-700 whitespace-nowrap`}>
                      {account || <span className="text-slate-600">Not set</span>}
                      {a.region && <span className="block text-xs text-slate-600">{a.region}</span>}
                      {a.tenant_id && <span className="block text-xs text-slate-600 xl:hidden">Tenant: {tenant.label}</span>}
                    </td>
                    <td className={`${CELL} ${WIDE_ONLY}`}>
                      {/* An agent with no registration has no lifecycle; its state already says so. */}
                      {registered ? <Badge cls={lifecycle.cls} label={lifecycle.label} /> : <span className="text-slate-600">None</span>}
                    </td>
                  </tr>
                );
              })}
              {!loading && rows.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-600 text-sm">
                    {filtered ? 'No agents match the current filters.' : 'No agents in the inventory yet.'}
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
        subtitle="One inventory of every agent, registered or only detected running. Agents are created and changed through their descriptor and pipeline, not from this portal."
      />
      <AgentsTable />
    </Page>
  );
}
