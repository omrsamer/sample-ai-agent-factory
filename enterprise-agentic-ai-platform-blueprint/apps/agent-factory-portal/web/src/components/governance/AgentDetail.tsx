// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useParams, Link, useSearchParams } from 'react-router-dom';
import { agentsApi, isNotFound } from '../../api/client';
import type { Agent } from '../../api/client';
import { useFeatures } from '../../config/features';
import { useUser } from '../../contexts/UserContext';
import { resolveTab, visibleTabs } from './agentDetailTabs';
import { identityStatusLabel, platformLabel, runtimeHandleField } from './platformLabels';
import { AgentAvatar, lifecycleBadge, originBadge, emailAlias, tenantBadge } from './agentUi';
import { resolveTenantName } from './tenantUi';
import AgentToolSubscriptionsTab from './AgentToolSubscriptionsTab';
import TracesTab from './agent-tabs/TracesTab';
import CostTab from './agent-tabs/CostTab';
import EvaluationsTab from './agent-tabs/EvaluationsTab';
import DeploymentTab from './agent-tabs/DeploymentTab';
import { Badge, CARD, CodeValue, ErrorCard, Field, Loading, Page, TabBar, formatDate } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

const AUTH_TYPE_META: Record<string, { label: string; cls: string }> = {
  none: { label: 'None recorded', cls: 'bg-slate-100 text-slate-600' },
  aws_iam: { label: 'AWS IAM (SigV4)', cls: 'bg-blue-50 text-blue-700' },
  entra: { label: 'OIDC bearer token', cls: 'bg-blue-50 text-blue-700' },
  api_key: { label: 'API key', cls: 'bg-violet-50 text-violet-700' },
};

function authTypeMeta(authType: string): { label: string; cls: string } {
  return Object.prototype.hasOwnProperty.call(AUTH_TYPE_META, authType)
    ? AUTH_TYPE_META[authType]
    : { label: authType || 'None recorded', cls: 'bg-slate-100 text-slate-600' };
}

const BACK_LINK = 'text-xs text-slate-600 hover:text-slate-700';

/** Read-only detail of one agent. The active tab is kept in the `tab` query parameter. */
export default function AgentDetail() {
  const { id = '' } = useParams();
  const { user } = useUser();
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: agent, loading, error, cause, reload } = useAsync(() => agentsApi.get(id), [id], 'Failed to load agent.');

  if (loading) {
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

  const tabs = visibleTabs(agent.origin);
  const activeTab = resolveTab(tabs, searchParams.get('tab'));
  const lifecycle = lifecycleBadge(agent.lifecycle_state);
  const origin = originBadge(agent.origin);

  return (
    <Page>
      <Link to="/agents" className={BACK_LINK}>← Agents</Link>
      <div className="mt-2 mb-5 flex items-center gap-3 min-w-0">
        <AgentAvatar name={agent.name} size="lg" />
        <div className="min-w-0">
          <h1 className="text-xl font-semibold text-slate-900 truncate">{agent.name}</h1>
          <div className="flex flex-wrap items-center gap-1.5 mt-1">
            <Badge cls={lifecycle.cls} label={lifecycle.label} />
            <Badge cls={origin.cls} label={origin.label} />
            <span className="text-xs text-slate-600">{platformLabel(agent.platform)}</span>
          </div>
        </div>
      </div>

      <TabBar
        tabs={tabs}
        active={activeTab.id}
        label="Agent sections"
        onSelect={(tab) => setSearchParams(tab === tabs[0].id ? {} : { tab }, { replace: true })}
      />

      {activeTab.id === 'overview' ? (
        <OverviewTab agent={agent} tenantName={resolveTenantName(agent.tenant_id, user?.tenants)} />
      ) : activeTab.id === 'tool-subscriptions' ? (
        <AgentToolSubscriptionsTab agent={agent} />
      ) : activeTab.id === 'deployment' ? (
        <DeploymentTab agent={agent} />
      ) : activeTab.id === 'traces' ? (
        <TracesTab agent={agent} />
      ) : activeTab.id === 'cost' ? (
        <CostTab agentId={agent.id} />
      ) : (
        <EvaluationsTab agentId={agent.id} />
      )}
    </Page>
  );
}

function OverviewTab({ agent, tenantName }: { agent: Agent; tenantName: string | null }) {
  const auth = authTypeMeta(agent.auth_type);
  const tenant = tenantBadge(tenantName ?? agent.tenant_id);
  const handle = runtimeHandleField(agent);
  const discovered = agent.lifecycle_state === 'discovered';
  const { governedActions } = useFeatures();

  return (
    <div className="space-y-5">
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
          <Field label="Caller authentication"><Badge cls={auth.cls} label={auth.label} /></Field>
          {handle && (
            <Field className="lg:col-span-2" label={handle.label}><CodeValue value={handle.value} copyLabel={handle.copyLabel} /></Field>
          )}
        </dl>
      </div>

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-3">Ownership and governance</h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
          <Field label="Tenant"><Badge cls={tenant.cls} label={tenant.label} title={agent.tenant_id ?? undefined} /></Field>
          <Field label="Business unit">{agent.business_unit ?? '—'}</Field>
          <Field label="Owner">
            {agent.sponsor_email ? (
              <span title={agent.sponsor_email}>{emailAlias(agent.sponsor_email)}</span>
            ) : (
              <span className="text-slate-600">Unassigned</span>
            )}
          </Field>
          <Field label="Region">{agent.region ?? '—'}</Field>
          <Field label="Data classification">{agent.data_classification ?? '—'}</Field>
          <Field label="Platform">{platformLabel(agent.platform)}</Field>
          <Field label="Framework">{agent.framework ?? '—'}</Field>
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
              <Field label="Registry id"><span className="font-mono text-xs break-all">{agent.id}</span></Field>
              {agent.record_name && (
                <Field label="Registry record name"><span className="font-mono text-xs break-all">{agent.record_name}</span></Field>
              )}
            </>
          )}
          <Field label="Created by">{agent.created_by ?? '—'}</Field>
          <Field label="Created">{formatDate(agent.created_at)}</Field>
          <Field label="Updated">{formatDate(agent.updated_at)}</Field>
        </dl>
      </div>
    </div>
  );
}
