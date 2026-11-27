// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useParams, Link, useSearchParams } from 'react-router-dom';
import { isNotFound, mcpServersApi } from '../../api/client';
import type { McpServer } from '../../api/client';
import { useUser } from '../../contexts/UserContext';
import { AgentAvatar, lifecycleBadge, emailAlias, kindBadge, tenantBadge } from './agentUi';
import { enforcementLabel } from './cedarPosture';
import { mcpEndpoint, visibleMcpTabs } from './mcpServerDetailTabs';
import { identityStatusLabel } from './platformLabels';
import { resolveTenantName } from './tenantUi';
import CedarPoliciesTab from './CedarPoliciesTab';
import McpConnectedAgentsTab from './McpConnectedAgentsTab';
import { Badge, CARD, CodeValue, ErrorCard, Field, Loading, Page, TabBar, formatDate } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

const BACK_LINK = 'text-xs text-slate-500 hover:text-slate-700';

/** Read-only detail of one tool gateway. The active tab is kept in the `tab` query parameter. */
export default function McpServerDetail() {
  const { id = '' } = useParams();
  const { user } = useUser();
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: mcp, loading, error, cause, reload } = useAsync(() => mcpServersApi.get(id), [id], 'Failed to load tool gateway.');

  if (loading) {
    return (
      <Page>
        <Loading label="Loading tool gateway…" />
      </Page>
    );
  }
  if (isNotFound(cause)) {
    return (
      <Page>
        <p className="text-slate-500 text-sm">
          Tool gateway <span className="font-mono">{id}</span> was not found.{' '}
          <Link to="/tool-gateways" className="text-blue-700 hover:underline">Back to tool gateways</Link>.
        </p>
      </Page>
    );
  }
  if (error || !mcp) {
    return (
      <Page>
        <Link to="/tool-gateways" className={BACK_LINK}>← Tool gateways</Link>
        <div className="mt-4">
          <ErrorCard title="Couldn’t load tool gateway" message={error ?? 'No data was returned.'} onRetry={reload} />
        </div>
      </Page>
    );
  }

  const tabs = visibleMcpTabs(mcp.kind);
  const active = tabs.find((t) => t.id === searchParams.get('tab')) ?? tabs[0];
  const lifecycle = lifecycleBadge(mcp.lifecycle_state);
  const kind = kindBadge(mcp.kind);

  return (
    <Page>
      <Link to="/tool-gateways" className={BACK_LINK}>← Tool gateways</Link>
      <div className="mt-2 mb-5 flex items-center gap-3 min-w-0">
        <AgentAvatar name={mcp.name} size="lg" />
        <div className="min-w-0">
          <h1 className="text-xl font-semibold text-slate-900 truncate">{mcp.name}</h1>
          <div className="flex flex-wrap items-center gap-1.5 mt-1">
            <Badge cls={lifecycle.cls} label={lifecycle.label} />
            <Badge cls={kind.cls} label={kind.label} />
            {mcp.shared && <Badge cls="bg-violet-50 text-violet-700" label="Shared with all tenants" />}
            <span className="text-xs text-slate-500">v{mcp.version}</span>
          </div>
        </div>
      </div>

      <TabBar
        tabs={tabs}
        active={active.id}
        label="Tool gateway sections"
        onSelect={(tab) => setSearchParams(tab === tabs[0].id ? {} : { tab }, { replace: true })}
      />

      {active.id === 'overview' ? (
        <OverviewTab mcp={mcp} tenantName={resolveTenantName(mcp.tenant_id, user?.tenants)} />
      ) : active.id === 'tools' ? (
        <ToolsTab mcp={mcp} />
      ) : active.id === 'policies' ? (
        <CedarPoliciesTab mcp={mcp} />
      ) : (
        <McpConnectedAgentsTab mcp={mcp} />
      )}
    </Page>
  );
}

function OverviewTab({ mcp, tenantName }: { mcp: McpServer; tenantName: string | null }) {
  const endpoint = mcpEndpoint(mcp);
  const tenant = tenantBadge(tenantName ?? mcp.tenant_id);
  const isGateway = mcp.kind === 'gateway' || !!mcp.gateway_arn || !!mcp.gateway_url;

  return (
    <div className="space-y-5">
      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-1">Description</h2>
        <p className="text-sm text-slate-700 whitespace-pre-wrap">
          {mcp.description ? mcp.description : <span className="text-slate-400">No description.</span>}
        </p>
      </div>

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-3">Connection</h2>
        <dl className="grid grid-cols-1 lg:grid-cols-2 gap-x-8 gap-y-4">
          <div className="lg:col-span-2">
            <Field label={endpoint?.fromGateway ? 'Gateway URL' : 'Endpoint URL'}>
              <CodeValue value={endpoint?.url} copyLabel="endpoint URL" />
            </Field>
          </div>
          {isGateway && (
            <div className="lg:col-span-2">
              <Field label="Gateway ARN"><CodeValue value={mcp.gateway_arn} copyLabel="gateway ARN" /></Field>
            </div>
          )}
          {mcp.runtime_arn && (
            <div className="lg:col-span-2">
              <Field label="Runtime ARN"><CodeValue value={mcp.runtime_arn} copyLabel="runtime ARN" /></Field>
            </div>
          )}
          {isGateway && <Field label="Cedar enforcement">{enforcementLabel(mcp.cedar_enforcement_mode)}</Field>}
          {isGateway && (
            <Field label="Policy engine">
              {mcp.cedar_policy_engine_id ? (
                <span className="font-mono text-xs break-all">{mcp.cedar_policy_engine_id}</span>
              ) : (
                <span className="text-slate-400">None attached</span>
              )}
            </Field>
          )}
        </dl>
      </div>

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-3">Ownership and governance</h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
          <Field label="Tenant">
            {mcp.shared ? (
              <Badge cls="bg-violet-50 text-violet-700" label="Shared with all tenants" />
            ) : (
              <Badge cls={tenant.cls} label={tenant.label} title={mcp.tenant_id ?? undefined} />
            )}
          </Field>
          <Field label="Business unit">{mcp.business_unit ?? '—'}</Field>
          <Field label="Owner">
            {mcp.owner_email ? <span title={mcp.owner_email}>{emailAlias(mcp.owner_email)}</span> : <span className="text-slate-400">Unassigned</span>}
          </Field>
          <Field label="Region">{mcp.region ?? '—'}</Field>
          <Field label="Data classification">{mcp.data_classification ?? '—'}</Field>
          <Field label="Workload identity">{identityStatusLabel(mcp.identity_status)}</Field>
        </dl>
      </div>

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-3">Record</h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
          <Field label="Registry id"><span className="font-mono text-xs break-all">{mcp.id}</span></Field>
          <Field label="Created by">{mcp.created_by ?? '—'}</Field>
          <Field label="Created">{formatDate(mcp.created_at)}</Field>
          <Field label="Updated">{formatDate(mcp.updated_at)}</Field>
        </dl>
      </div>
    </div>
  );
}

function ToolsTab({ mcp }: { mcp: McpServer }) {
  const tools = mcp.available_tools ?? [];
  if (tools.length === 0) {
    return <div className={`${CARD} p-8 text-center text-slate-500 text-sm`}>No tools are recorded for this gateway.</div>;
  }
  return (
    <div className="space-y-3">
      <p className="text-[11px] uppercase tracking-wide text-slate-400 font-medium">
        {tools.length} {tools.length === 1 ? 'tool' : 'tools'}
      </p>
      {tools.map((tool, i) => (
        <div key={`${tool.name}-${i}`} className={`${CARD} p-5`}>
          <code className="text-sm font-mono font-semibold text-slate-800 break-all">{tool.name}</code>
          {tool.description && <p className="text-sm text-slate-600 mt-1 whitespace-pre-wrap">{tool.description}</p>}
          <details className="mt-3">
            <summary className="text-[11px] uppercase tracking-wide text-slate-500 font-medium cursor-pointer">Input schema</summary>
            <pre className="mt-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg p-3 overflow-x-auto text-slate-700">
              {JSON.stringify(tool.input_schema ?? {}, null, 2)}
            </pre>
          </details>
        </div>
      ))}
    </div>
  );
}
