// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react';
import { useParams, Link, useSearchParams } from 'react-router-dom';
import { agentsApi, isNotFound } from '../../api/client';
import type { Agent } from '../../api/client';
import { useFeatures } from '../../config/features';
import { useUser } from '../../contexts/UserContext';
import { resolveTab, visibleTabs } from './agentDetailTabs';
import { identityStatusLabel, inboundAuthorizerLabel, platformLabel, runtimeHandleField } from './platformLabels';
import { AgentAvatar, BreakableName, lifecycleBadge, tenantBadge } from './agentUi';
import { AgentChips, AgentRisk, ContainedBadge, InventoryStateBadge } from './InventoryBadges';
import {
  accountLabel,
  agentContext,
  createdByLabel,
  detectionSourceLabel,
  flagState,
  hasRegistration,
  lastInvokedText,
  lastReviewedText,
  noReaderSentence,
  ownerGroupLine,
  readerState,
  reasonText,
  CLOSED_RETIRED_NOTE,
  CLOSED_RISK_NOTE,
  RETIRED_FOLLOW_UP,
  obligationsClosed,
  retiredRuntimeReason,
  reviewByOf,
  severityLabel,
  sponsorLine,
  withVerifiedContainment,
  withVerifiedFields,
  type OwnershipLine,
  type VerifiedContainment,
  type VerifiedFields,
} from './inventory';
import OmniLink, { OMNI_NOTE } from '../shared/OmniLink';
import { resolveTenantName } from './tenantUi';
import AgentToolSubscriptionsTab from './AgentToolSubscriptionsTab';
import EvidenceDownload from './EvidenceDownload';
import { NoReaderCard } from './agent-tabs/ObsEmptyCard';
import TracesTab from './agent-tabs/TracesTab';
import CostTab from './agent-tabs/CostTab';
import EvaluationsTab from './agent-tabs/EvaluationsTab';
import DeploymentTab from './agent-tabs/DeploymentTab';
import { Badge, CARD, CodeValue, ErrorCard, Field, Loading, MaskedText, NOT_SET, Page, TabBar, formatDate } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

const AUTH_TYPE_META: Record<string, { label: string; cls: string }> = {
  none: { label: 'None recorded', cls: 'bg-slate-100 text-slate-600' },
  aws_iam: { label: 'AWS IAM (SigV4)', cls: 'bg-blue-50 text-blue-700' },
  custom_jwt: { label: 'JSON Web Token (custom authorizer)', cls: 'bg-blue-50 text-blue-700' },
  api_key: { label: 'API key', cls: 'bg-violet-50 text-violet-700' },
};

function authTypeMeta(authType: string): { label: string; cls: string } {
  return Object.prototype.hasOwnProperty.call(AUTH_TYPE_META, authType)
    ? AUTH_TYPE_META[authType]
    : { label: authType || 'None recorded', cls: 'bg-slate-100 text-slate-600' };
}

const BACK_LINK = 'text-xs text-slate-600 hover:text-slate-700';

// A little longer than the API's cache of an agent (30 seconds by default).
const AGENT_SETTLE_SECONDS = 35;

const LINE_TONE: Record<OwnershipLine['tone'], string> = { value: 'break-words', muted: 'text-slate-600', warn: 'text-amber-900' };

/** One value of the ownership card. What needs a person's attention is said in words. */
function Ownership({ line }: { line: OwnershipLine }) {
  return (
    <>
      <span className={LINE_TONE[line.tone]}>{line.text}</span>
      {line.note && <span className="block text-amber-900">{line.note}</span>}
    </>
  );
}

// Containment belongs to the governed actions feature. This import runs only when the tab is
// rendered, and the tab exists only when the feature is on.
const ContainmentTab = lazy(() => import('../../actions/ContainmentTab'));
// The registration behind the agent, with its review and retirement. The same feature, and the
// same rule: imported only when it is rendered, and rendered only when the feature is on.
const AgentRegistrationPanel = lazy(() => import('../../actions/AgentRegistrationPanel'));

/** Read-only detail of one agent. The active tab is kept in the `tab` query parameter. */
export default function AgentDetail() {
  const { id = '' } = useParams();
  const { user } = useUser();
  const [searchParams, setSearchParams] = useSearchParams();
  // A reload after an action keeps the page, and the tab's own state, on screen.
  const { data: loaded, loading, error, cause, reload } = useAsync(() => agentsApi.get(id), [id], 'Failed to load agent.', {
    keepPreviousOnReload: true,
  });
  const { governedActions } = useFeatures();
  // The state a contain or release on this page has just verified. The API serves an agent's
  // flags from a short cache, so the record read right after the action can still be the old one.
  const [verified, setVerified] = useState<VerifiedContainment | null>(null);
  // The same for a review or a retirement made from this page: the review date and the lifecycle.
  const [verifiedFields, setVerifiedFields] = useState<VerifiedFields | null>(null);
  // What an action changes elsewhere on the record (its risk and its reasons, whether its
  // obligations are closed) is only assessed again once that cache has expired. So after an
  // action the agent is read once more, a little later and quietly: a read that fails changes
  // nothing on screen.
  const [settleFor, setSettleFor] = useState<{ id: string; n: number } | null>(null);
  const [reread, setReread] = useState<{ after: Agent; agent: Agent } | null>(null);
  const current = reread && reread.after === loaded ? reread.agent : loaded;
  useEffect(() => {
    if (!settleFor || settleFor.id !== id || !loaded) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      agentsApi.get(id).then(
        (next) => {
          if (!cancelled) setReread({ after: loaded, agent: next });
        },
        () => undefined,
      );
    }, AGENT_SETTLE_SECONDS * 1000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [settleFor, loaded, id]);
  const settleLater = () => setSettleFor((was) => ({ id, n: (was?.n ?? 0) + 1 }));
  const agent = current ? withVerifiedFields(withVerifiedContainment(current, verified), verifiedFields) : current;

  if (loading && !agent) {
    return (
      <Page>
        <Loading label="Loading agent…" />
      </Page>
    );
  }
  if (isNotFound(cause)) {
    return (
      <Page>
        <p className="text-slate-600 text-sm">
          Agent <span className="font-mono">{id}</span> was not found.{' '}
          <Link to="/agents" className="text-blue-700 hover:underline">Back to agents</Link>.
        </p>
      </Page>
    );
  }
  if (error || !agent) {
    return (
      <Page>
        <Link to="/agents" className={BACK_LINK}>← Agents</Link>
        <div className="mt-4">
          <ErrorCard title="Couldn’t load agent" message={error ?? 'No data was returned.'} onRetry={reload} />
        </div>
      </Page>
    );
  }

  const tabs = visibleTabs(agent.origin, { governedActions });
  const activeTab = resolveTab(tabs, searchParams.get('tab'));
  const lifecycle = lifecycleBadge(agent.lifecycle_state);
  const registered = hasRegistration(agent);
  // Without a reader role in the agent's account nothing can be read from its runtime: each of
  // those tabs says so instead of asking the API.
  const noReader = readerState(agent) === 'none';
  // Two agents can carry one name: the tenant and the account tell them apart.
  const context = agentContext(agent, resolveTenantName(agent.tenant_id, user?.tenants));

  return (
    <Page>
      <Link to="/agents" className={BACK_LINK}>← Agents</Link>
      <div className="mt-2 mb-5 flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
       <div className="flex items-center gap-3 min-w-0">
        <AgentAvatar name={agent.name} size="lg" />
        <div className="min-w-0">
          <h1 className="text-xl font-semibold text-slate-900"><BreakableName name={agent.name} /></h1>
          {context && <p className="text-sm text-slate-600">{context}</p>}
          <div className="flex flex-wrap items-center gap-1.5 mt-1">
            <ContainedBadge agent={agent} />
            <InventoryStateBadge state={agent.inventory_state} />
            <AgentRisk agent={agent} />
            {/* The lifecycle belongs to a registration; an agent without one has none. */}
            {registered && <Badge cls={lifecycle.cls} label={lifecycle.label} />}
            <AgentChips agent={agent} />
            {agent.platform && <span className="text-xs text-slate-600">{platformLabel(agent.platform)}</span>}
          </div>
        </div>
       </div>
       {/* For every role that can read the agent: one document for an auditor. */}
       <EvidenceDownload agentId={agent.id} agentName={agent.name} />
      </div>

      <TabBar
        tabs={tabs}
        active={activeTab.id}
        label="Agent sections"
        onSelect={(tab) => setSearchParams(tab === tabs[0].id ? {} : { tab }, { replace: true })}
      />

      {activeTab.id === 'overview' ? (
        <OverviewTab
          agent={agent}
          tenantName={resolveTenantName(agent.tenant_id, user?.tenants)}
          registrationPanel={
            // Review and retirement belong to the governed actions feature and to a registered agent.
            governedActions && registered ? (
              <Suspense fallback={<Loading label="Loading…" />}>
                <AgentRegistrationPanel
                  agent={agent}
                  onChanged={(fields) => {
                    setVerifiedFields({ id: agent.id, fields });
                    reload();
                    settleLater();
                  }}
                />
              </Suspense>
            ) : null
          }
        />
      ) : activeTab.id === 'tool-subscriptions' ? (
        // A registered agent's subscriptions come from its record. An unregistered one's are read
        // from its runtime, which needs the reader role.
        noReader && !registered ? (
          <NoReaderCard body={noReaderSentence('the tool gateways it calls')} />
        ) : (
          <AgentToolSubscriptionsTab agent={agent} />
        )
      ) : activeTab.id === 'deployment' ? (
        noReader ? <NoReaderCard body={noReaderSentence('its runtime status and deployments')} /> : <DeploymentTab agent={agent} />
      ) : activeTab.id === 'traces' ? (
        <div className="space-y-4">
          {agent.omni_url && (
            <div className={`${CARD} p-4 flex flex-wrap items-center justify-between gap-3`}>
              <p className="text-sm text-slate-700">{OMNI_NOTE}</p>
              <OmniLink url={agent.omni_url} subject={agent.name} />
            </div>
          )}
          {noReader ? <NoReaderCard body={noReaderSentence('its traces')} /> : <TracesTab agent={agent} />}
        </div>
      ) : activeTab.id === 'cost' ? (
        noReader ? <NoReaderCard body={noReaderSentence('its usage and cost')} /> : <CostTab agentId={agent.id} />
      ) : activeTab.id === 'containment' && governedActions ? (
        <Suspense fallback={<Loading label="Loading…" />}>
          <ContainmentTab
            agent={agent}
            onChanged={(state) => {
              // Only a verified state is taken over; after a failure the API's own flag stands.
              setVerified(state === 'contained' || state === 'not_contained' ? { id: agent.id, contained: state === 'contained' } : null);
              reload();
              settleLater();
            }}
          />
        </Suspense>
      ) : (
        <EvaluationsTab agentId={agent.id} />
      )}
    </Page>
  );
}

function OverviewTab({ agent, tenantName, registrationPanel }: { agent: Agent; tenantName: string | null; registrationPanel: ReactNode }) {
  const auth = authTypeMeta(agent.auth_type);
  const tenant = tenantBadge(tenantName ?? agent.tenant_id);
  const handle = runtimeHandleField(agent);
  const discovered = agent.lifecycle_state === 'discovered';
  const { governedActions } = useFeatures();
  const reviewBy = reviewByOf(agent);
  const sources = agent.detection_sources ?? [];
  const contact = (agent.governance?.contact ?? '').trim();
  const overdue = flagState(agent.flags, 'review_overdue');
  const account = accountLabel(agent);
  const createdBy = createdByLabel(agent);
  const retired = agent.lifecycle_state === 'deprecated';
  const closed = obligationsClosed(agent);
  const stillDeployed = retiredRuntimeReason(agent);
  const reasons = agent.risk?.reasons ?? [];

  return (
    <div className="space-y-5">
      {retired && (
        // Amber while something is left to do; plain once nothing is deployed.
        <section aria-labelledby="agent-retired" className={`rounded-xl border p-5 ${closed ? 'border-slate-300 bg-slate-50' : 'border-amber-300 bg-amber-50'}`}>
          <h2 id="agent-retired" className="text-sm font-semibold text-slate-900">Registration retired</h2>
          {stillDeployed ? (
            <>
              <p className="text-sm text-slate-900 mt-1">{stillDeployed}</p>
              <p className="text-sm text-slate-800 mt-1">{RETIRED_FOLLOW_UP}</p>
            </>
          ) : (
            <p className="text-sm text-slate-800 mt-1">
              {closed ? CLOSED_RETIRED_NOTE : 'This agent’s registration is retired, which is permanent. To bring the agent back, register it again.'}
            </p>
          )}
        </section>
      )}

      <section aria-labelledby="risk-why" className={`${CARD} p-5`}>
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <h2 id="risk-why" className="text-sm font-semibold text-slate-800">{closed ? 'Risk' : 'Why this risk level'}</h2>
          <AgentRisk agent={agent} />
        </div>
        {closed ? (
          // No rule applies to a retired registration with nothing deployed: there is no level to explain.
          <p className="text-sm text-slate-700">{CLOSED_RISK_NOTE}</p>
        ) : !agent.risk ? (
          <p className="text-sm text-slate-600">Risk has not been assessed for this agent.</p>
        ) : reasons.length === 0 ? (
          <p className="text-sm text-slate-600">No reason was recorded for this level.</p>
        ) : (
          <ul className="space-y-1.5">
            {reasons.map((reason, i) => (
              <li key={`${reason.code}-${i}`} className="flex flex-wrap items-baseline gap-2 text-sm">
                <span className="text-xs font-semibold text-slate-700 w-16 shrink-0">{severityLabel(reason.severity)}</span>
                <span className="text-slate-800 min-w-0 flex-1 break-words">{reasonText(reason)}</span>
                {reason.code && <code className="text-[11px] font-mono text-slate-600 break-all">{reason.code}</code>}
              </li>
            ))}
          </ul>
        )}
      </section>

      {registrationPanel}

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-1">Purpose</h2>
        <p className="text-sm text-slate-700 whitespace-pre-wrap">
          {agent.purpose ? agent.purpose : <span className="text-slate-600">No purpose described.</span>}
        </p>
      </div>

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-3">Invocation</h2>
        <dl className="grid grid-cols-1 lg:grid-cols-2 gap-x-8 gap-y-4">
          <Field className="lg:col-span-2" label="Endpoint URL"><CodeValue value={agent.endpoint_url} copyLabel="endpoint URL" /></Field>
          <Field label="Caller authentication">
            {agent.inbound_authorizer ? (
              <Badge
                cls={agent.inbound_authorizer === 'NONE' ? 'bg-red-50 text-red-800' : 'bg-blue-50 text-blue-800'}
                label={inboundAuthorizerLabel(agent.inbound_authorizer)}
              />
            ) : (
              <Badge cls={auth.cls} label={auth.label} />
            )}
          </Field>
          {handle && (
            <Field className="lg:col-span-2" label={handle.label}><CodeValue value={handle.value} copyLabel={handle.copyLabel} /></Field>
          )}
        </dl>
      </div>

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-3">Ownership and governance</h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
          <Field label="Tenant"><Badge cls={tenant.cls} label={tenant.label} title={agent.tenant_id ?? undefined} /></Field>
          <Field label="Owner group"><Ownership line={ownerGroupLine(agent)} /></Field>
          <Field label="Sponsor"><Ownership line={sponsorLine(agent)} /></Field>
          <Field label="Contact">{contact ? <span className="break-words">{contact}</span> : <span className="text-slate-600">None recorded</span>}</Field>
          <Field label="Review by">
            {reviewBy ? (
              <>
                {reviewBy}
                {overdue === 'set' && <span className="ml-2 text-amber-900 font-medium">Overdue</span>}
              </>
            ) : (
              <span className="text-slate-600">No review date</span>
            )}
          </Field>
          {hasRegistration(agent) && (
            <Field label="Last reviewed">
              {agent.last_reviewed_at ? <span className="break-words">{lastReviewedText(agent, formatDate)}</span> : <span className="text-slate-600">{lastReviewedText(agent, formatDate)}</span>}
            </Field>
          )}
          <Field label="Last invoked">{agent.last_invoked_on || <span className="text-slate-600">{lastInvokedText(agent)}</span>}</Field>
          <Field label="Detected by">
            {sources.length > 0 ? sources.map(detectionSourceLabel).join(', ') : <span className="text-slate-600">Not detected</span>}
          </Field>
          <Field label="Account">{account ? <span className="break-words">{account}</span> : <span className="text-slate-600">{NOT_SET}</span>}</Field>
          <Field label="Region">{agent.region ?? <span className="text-slate-600">{NOT_SET}</span>}</Field>
          <Field label="Data classification">{agent.data_classification ?? <span className="text-slate-600">{NOT_SET}</span>}</Field>
          <Field label="Platform">{platformLabel(agent.platform)}</Field>
          <Field label="Framework">{agent.framework ?? <span className="text-slate-600">{NOT_SET}</span>}</Field>
          <Field label="Workload identity">{identityStatusLabel(agent.identity_status)}</Field>
        </dl>
      </div>

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-3">Record</h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
          {discovered ? (
            <>
              <Field label="Registry record">
                <span className="text-slate-700">Not registered</span>
                {governedActions && (
                  <Link
                    to={`/registrations/new?from=${encodeURIComponent(agent.id)}`}
                    className="ml-2 text-blue-700 hover:underline"
                  >
                    Register this agent
                  </Link>
                )}
              </Field>
              <Field label="Runtime id"><span className="font-mono text-xs break-all">{agent.id}</span></Field>
            </>
          ) : (
            <>
              <Field label="Registry record id"><span className="font-mono text-xs break-all">{agent.id}</span></Field>
              {agent.record_name && (
                <Field label="Registry record name"><span className="font-mono text-xs break-all">{agent.record_name}</span></Field>
              )}
            </>
          )}
          <Field label="Created by"><MaskedText value={createdBy} /></Field>
          <Field label="Created">{formatDate(agent.created_at)}</Field>
          <Field label="Updated">{formatDate(agent.updated_at)}</Field>
        </dl>
      </div>
    </div>
  );
}
