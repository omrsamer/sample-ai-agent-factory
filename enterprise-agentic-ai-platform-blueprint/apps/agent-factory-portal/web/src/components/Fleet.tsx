// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { agentsApi, fleetApi, omniApi } from '../api/client';
import type { Agent, UserTenant } from '../api/client';
import { attentionList, attentionTiles, gatewaysLine, partitionTiles, riskTiles, summaryNotes, type SummaryTile } from './fleetSummary';
import { useUser } from '../contexts/UserContext';
import { cellStateView, fleetTotals, sortCells } from './fleetHealth';
import { DataNotes } from './governance/agent-tabs/ObsEmptyCard';
import { BreakableName, lifecycleBadge } from './governance/agentUi';
import { AgentChips, ContainedBadge, InventoryStateBadge, RiskBadge } from './governance/InventoryBadges';
import {
  OBSERVED_WINDOWS,
  agentContext,
  hasRegistration,
  humanise,
  notReadLine,
  observedBy,
  observedNotes,
  observedTag,
  reasonText,
  windowWords,
} from './governance/inventory';
import { resolveTenantName } from './governance/tenantUi';
import OmniLink, { OMNI_NOTE } from './shared/OmniLink';
import { Badge, CARD, ErrorCard, Loading, Page, PageHeader, TABLE_HEAD, TD, TH, formatDate } from './shared/ui';
import { useAsync } from './shared/useAsync';

const ATTENTION_SHOWN = 8;

/** A count that links to the agents list filtered to what it counts. Unknown is said in words, never as zero. */
function Tile({ tile }: { tile: SummaryTile }) {
  const known = tile.value !== null;
  const active = known && (tile.value ?? 0) > 0;
  const valueCls = !active ? 'text-slate-900' : tile.tone === 'critical' ? 'text-red-700' : tile.tone === 'attention' ? 'text-amber-800' : 'text-slate-900';
  return (
    <li className={`${CARD} p-4 flex flex-col`}>
      <Link to={tile.to} className="block rounded-lg">
        <span className={`block font-semibold tabular-nums ${known ? `text-2xl ${valueCls}` : 'text-base text-slate-700 py-1'}`}>
          {known ? tile.value : 'Unknown'}
        </span>{' '}
        <span className="block text-sm font-medium text-slate-800 mt-0.5 underline decoration-slate-300 underline-offset-2">{tile.label}</span>
        <span className="sr-only">. {tile.hint} Show these agents.</span>
      </Link>
      <span className="block text-xs text-slate-600 mt-0.5">{known ? tile.hint : 'Could not be counted.'}</span>
      {tile.unreadable && (
        <Link to={tile.unreadable.to} className="text-xs text-blue-700 underline mt-1">
          {tile.unreadable.count} not readable
        </Link>
      )}
    </li>
  );
}

/** One agent to look at first: what tells it apart, why it is listed, and the reasons in the API's sentences. */
function AttentionRow({ agent, tenants }: { agent: Agent; tenants: UserTenant[] | undefined }) {
  const reasons = (agent.risk?.reasons ?? []).map(reasonText);
  const context = agentContext(agent, resolveTenantName(agent.tenant_id, tenants));
  const registered = hasRegistration(agent);
  const lifecycle = lifecycleBadge(agent.lifecycle_state);
  return (
    <li className="px-5 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span>
          <Link to={`/agents/${encodeURIComponent(agent.id)}`} className="font-medium text-blue-700 hover:underline">
            <BreakableName name={agent.name} />
          </Link>
          {/* Two agents can carry one name: the tenant and the account tell them apart. */}
          {context && <span className="text-sm text-slate-600"> · {context}</span>}
        </span>
        <RiskBadge level={agent.risk?.level} />
        <ContainedBadge agent={agent} />
        {!registered && <InventoryStateBadge state={agent.inventory_state} />}
        {registered && agent.lifecycle_state !== 'approved' && <Badge cls={lifecycle.cls} label={lifecycle.label} />}
        <AgentChips agent={agent} />
      </div>
      {reasons.length > 0 && (
        <ul className="mt-1 text-sm text-slate-700 list-disc list-inside">
          {reasons.map((r) => (
            <li key={r} className="break-words">{r}</li>
          ))}
        </ul>
      )}
    </li>
  );
}

/**
 * Home screen, arranged around what needs attention: inventory and risk counts that open the
 * filtered agents list, the agents to look at first, the health of every Workstream cell, and
 * the agents seen in telemetry.
 */
export default function Fleet() {
  const { user } = useUser();
  const [hours, setHours] = useState(OBSERVED_WINDOWS[0].hours);
  const summary = useAsync(() => fleetApi.summary(), [], 'Failed to load the fleet summary.');
  const agents = useAsync(() => agentsApi.list(), [], 'Failed to load agents.');
  const health = useAsync(() => fleetApi.health(), [], 'Failed to load fleet health.');
  const observed = useAsync(() => omniApi.observedServices(hours), [hours], 'Failed to load the agents seen in telemetry.');

  const agentById = useMemo(() => new Map((agents.data ?? []).map((a) => [a.id, a])), [agents.data]);
  const cells = useMemo(() => sortCells(health.data?.cells ?? []), [health.data]);
  const healthTotals = fleetTotals(health.data);
  const attention = useMemo(() => attentionList(agents.data, ATTENTION_SHOWN), [agents.data]);
  const anyOmni = cells.some((c) => !!c.omni_url);
  const services = observed.data?.services ?? [];
  const gateways = gatewaysLine(summary.data);
  const observedWhere = observedBy(observed.data?.domains);
  const observedWindow = windowWords(observed.data?.window_hours ?? hours);
  const { skipped, notes: observedProblems } = observedNotes(observed.data?.warnings);
  const notRead = notReadLine(skipped);

  return (
    <Page>
      <PageHeader
        title="Fleet"
        subtitle="Every agent the factory knows about, registered or only detected, and what needs attention first. Cells change only through their pipeline."
      />

      <section aria-labelledby="fleet-inventory" className="mb-8">
        <h2 id="fleet-inventory" className="text-base font-semibold text-slate-900 mb-3">Inventory</h2>
        {summary.loading ? (
          <Loading label="Loading the fleet summary…" />
        ) : summary.error ? (
          <ErrorCard title="Couldn’t load the fleet summary" message={summary.error} onRetry={summary.reload} />
        ) : (
          <>
            <DataNotes notes={summaryNotes(summary.data)} />
            {/* Agents = Approved + Awaiting approval + Not registered. */}
            <ul className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-2" aria-label="Agents by registration">
              {partitionTiles(summary.data).map((tile) => (
                <Tile key={tile.id} tile={tile} />
              ))}
            </ul>
            <ul className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3" aria-label="Agents that need attention">
              {attentionTiles(summary.data).map((tile) => (
                <Tile key={tile.id} tile={tile} />
              ))}
            </ul>

            <h3 className="text-sm font-semibold text-slate-900 mt-5 mb-2">Risk</h3>
            <ul className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {riskTiles(summary.data, agents.data).map((tile) => (
                <Tile key={tile.id} tile={tile} />
              ))}
            </ul>
            <p className="text-xs text-slate-600 mt-3">
              {gateways ? `${gateways} ` : ''}
              <Link to="/tool-gateways" className="text-blue-700 underline">See the tool gateways</Link>
            </p>
          </>
        )}
      </section>

      <section aria-labelledby="fleet-attention" className="mb-8">
        <h2 id="fleet-attention" className="text-base font-semibold text-slate-900 mb-3">Needs attention</h2>
        {agents.loading ? (
          <Loading label="Loading…" />
        ) : agents.error ? (
          <ErrorCard title="Couldn’t load agents" message={agents.error} onRetry={agents.reload} />
        ) : attention.total === 0 ? (
          <div className={`${CARD} p-5 text-sm text-slate-600`}>No agent is at high risk, contained, ownerless or overdue for review.</div>
        ) : (
          <>
            <ul className={`${CARD} divide-y divide-slate-100`}>
              {attention.shown.map((entry) => (
                <AttentionRow key={entry.agent.id} agent={entry.agent} tenants={user?.tenants} />
              ))}
            </ul>
            {attention.total > attention.shown.length && (
              <p className="text-xs text-slate-600 mt-2">
                Showing {attention.shown.length} of {attention.total}. <Link to="/agents" className="text-blue-700 underline">See all agents</Link>
              </p>
            )}
          </>
        )}
      </section>

      <section aria-labelledby="fleet-health-heading" className="mb-8">
        <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
          <h2 id="fleet-health-heading" className="text-base font-semibold text-slate-900">Fleet health</h2>
          {health.data && (
            <span className="text-xs text-slate-600">
              {healthTotals.healthy} healthy · {healthTotals.needs_attention} need attention · {healthTotals.critical} critical ·{' '}
              {healthTotals.no_data} no data · checked {formatDate(health.data.checked_at)}
            </span>
          )}
        </div>
        {health.loading ? (
          <Loading label="Loading fleet health…" />
        ) : health.error ? (
          <ErrorCard title="Couldn’t load fleet health" message={health.error} onRetry={health.reload} />
        ) : cells.length === 0 ? (
          <div className={`${CARD} p-6 text-sm text-slate-600`}>No Workstream cells are reporting yet.</div>
        ) : (
          <div className={`${CARD} overflow-x-auto`}>
            <table className="w-full text-sm">
              <thead className={TABLE_HEAD}>
                <tr>
                  {/* A cell need not hold an agent, so the column names the cell. */}
                  <th scope="col" className={TH}>Cell</th>
                  <th scope="col" className={TH}>Tenant</th>
                  <th scope="col" className={TH}>Environment</th>
                  <th scope="col" className={TH}>Account · Region</th>
                  <th scope="col" className={TH}>State</th>
                  <th scope="col" className={`${TH} text-right`}>Alarms</th>
                  {anyOmni && <th scope="col" className={TH}><span className="sr-only">CloudWatch Omni</span></th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {cells.map((cell) => {
                  const view = cellStateView(cell.state);
                  const agent = cell.agent_ref ? agentById.get(cell.agent_ref) : undefined;
                  return (
                    <tr key={`${cell.tenant_id}/${cell.agent_id}/${cell.environment}`}>
                      <td className={TD}>
                        <span className="inline-flex flex-wrap items-center gap-1.5">
                          {cell.agent_ref ? (
                            <Link to={`/agents/${encodeURIComponent(cell.agent_ref)}`} className="font-medium text-blue-700 hover:underline">
                              <BreakableName name={agent?.name ?? cell.agent_id} />
                            </Link>
                          ) : (
                            <span className="font-medium text-slate-700"><BreakableName name={cell.agent_id} /></span>
                          )}
                          <ContainedBadge agent={agent} />
                        </span>
                      </td>
                      <td className={`${TD} text-slate-600`}>{resolveTenantName(cell.tenant_id, user?.tenants) ?? cell.tenant_id}</td>
                      <td className={`${TD} text-slate-600`}>{cell.environment}</td>
                      <td className={`${TD} text-slate-600`}>{cell.account_alias} · {cell.region}</td>
                      <td className={TD}>
                        <Badge cls={view.cls} label={view.label} title={cell.detail || (cell.reachable ? undefined : 'Telemetry for this cell could not be read.')} />
                      </td>
                      <td className={`${TD} text-right tabular-nums text-slate-700`}>{cell.reachable ? cell.alarms_in_alarm : 'Not read'}</td>
                      {anyOmni && (
                        <td className={`${TD} text-right`}>
                          <OmniLink url={cell.omni_url} subject={agent?.name ?? cell.agent_id} compact />
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {cells.length > 0 && cells.every((c) => c.state === 'no_data') && (
          <p className="text-xs text-slate-600 mt-2">
            No CloudWatch alarms were found for these cells; health is derived from alarms.
          </p>
        )}
        {anyOmni && <p className="text-xs text-slate-600 mt-2">{OMNI_NOTE}</p>}
      </section>

      <section aria-labelledby="fleet-observed">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 id="fleet-observed" className="text-base font-semibold text-slate-900">Observed in telemetry</h2>
          <div className="flex flex-wrap items-center gap-3">
            <span className="inline-flex items-center gap-2">
              <label htmlFor="observed-window" className="text-sm text-slate-700">Window</label>
              <select
                id="observed-window"
                className="px-2.5 py-1.5 text-sm rounded-lg border border-slate-400 bg-white"
                value={hours}
                onChange={(e) => setHours(Number(e.target.value))}
              >
                {OBSERVED_WINDOWS.map((w) => (
                  <option key={w.hours} value={w.hours}>{w.label}</option>
                ))}
              </select>
            </span>
            <OmniLink url={observed.data?.omni_url} />
          </div>
        </div>
        <p className="text-sm text-slate-600 mt-0.5 mb-3">
          The agents CloudWatch Omni observes in telemetry over {observedWindow}. One that matches no registered agent is running
          without a registration. {observedWhere ? `${observedWhere} ` : ''}{OMNI_NOTE}
        </p>
        {observed.loading ? (
          <Loading label="Loading what is observed in telemetry…" />
        ) : observed.error ? (
          <ErrorCard title="Couldn’t load what is observed in telemetry" message={observed.error} onRetry={observed.reload} />
        ) : (
          <>
            <DataNotes notes={observedProblems} />
            {services.length === 0 ? (
              <div className={`${CARD} p-5 text-sm text-slate-600 mt-2`}>No agent was observed by CloudWatch Omni in {observedWindow}.</div>
            ) : (
              <div className={`${CARD} overflow-x-auto mt-2`}>
                <table className="w-full text-sm">
                  <thead className={TABLE_HEAD}>
                    <tr>
                      <th scope="col" className={TH}>Agent</th>
                      <th scope="col" className={TH}>Region</th>
                      <th scope="col" className={TH}>Signals</th>
                      <th scope="col" className={TH}>Last observed</th>
                      <th scope="col" className={TH}>In the inventory</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {services.map((service, i) => {
                      const match = service.matched_agent_id ? agentById.get(service.matched_agent_id) : undefined;
                      const matchContext = match ? agentContext(match, resolveTenantName(match.tenant_id, user?.tenants)) : '';
                      const tag = observedTag(service);
                      return (
                        <tr key={`${service.name}/${service.resource_id ?? i}`}>
                          <td className={`${TD} font-medium text-slate-800`}><BreakableName name={service.name} /></td>
                          <td className={`${TD} text-slate-600`}>{service.region || 'Not set'}</td>
                          <td className={`${TD} text-slate-600`}>{(service.signals ?? []).map(humanise).join(', ') || 'None'}</td>
                          {/* A missing time is never shown as a date. */}
                          <td className={`${TD} text-slate-600 whitespace-nowrap`}>{formatDate(service.last_observed_at, 'Not observed')}</td>
                          <td className={TD}>
                            <span className="inline-flex flex-wrap items-center gap-1.5">
                              <Badge cls={tag.cls} label={tag.label} title={tag.hint} />
                              {service.matched_agent_id && (
                                <span>
                                  <Link to={`/agents/${encodeURIComponent(service.matched_agent_id)}`} className="text-blue-700 underline">
                                    <BreakableName name={match?.name ?? service.matched_agent_id} />
                                  </Link>
                                  {matchContext && <span className="text-slate-600"> · {matchContext}</span>}
                                </span>
                              )}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {/* An account that Omni cannot be read in is information, not a problem. */}
            {notRead && <p className="text-xs text-slate-600 mt-2">{notRead}</p>}
          </>
        )}
      </section>
    </Page>
  );
}
