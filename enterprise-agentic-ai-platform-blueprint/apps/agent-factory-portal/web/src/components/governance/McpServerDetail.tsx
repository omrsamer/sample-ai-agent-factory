// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useParams, Link, useSearchParams } from 'react-router-dom';
import { isNotFound, mcpServersApi } from '../../api/client';
import type { McpServer } from '../../api/client';
import { useUser } from '../../contexts/UserContext';
import { NoReaderCard } from './agent-tabs/ObsEmptyCard';
import { AgentAvatar, BreakableName, kindBadge, tenantBadge } from './agentUi';
import {
  CONNECTED_NOT_KNOWN,
  gatewayAccount,
  gatewayChip,
  gatewayDetectedBy,
  gatewayLifecycle,
  gatewayNotRead,
  knownTime,
  policyCell,
} from './gatewayView';
import { mcpEndpoint, visibleMcpTabs } from './mcpServerDetailTabs';
import { identityStatusLabel, inboundAuthorizerLabel } from './platformLabels';
import { resolveTenantName } from './tenantUi';
import CedarPoliciesTab from './CedarPoliciesTab';
import McpConnectedAgentsTab from './McpConnectedAgentsTab';
import { Badge, CARD, CodeValue, ErrorCard, Field, formatDate, Loading, MaskedText, NOT_SET, Page, TabBar } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

const NOT_RECORDED = 'Not recorded';

const BACK_LINK = 'text-xs text-slate-600 hover:text-slate-700';

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
        <p className="text-slate-600 text-sm">
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
  const state = gatewayLifecycle(mcp);
  const kind = kindBadge(mcp.kind);
  // A gateway that only the organization registry detected: nothing of its tools, its tenant,
  // its policy engine or its policies is known, so each panel says so and asks the API nothing.
  const notRead = gatewayNotRead(mcp);
  const chip = gatewayChip(mcp);
  // Two gateways can carry one name: the account and the Region tell them apart.
  const where = [gatewayAccount(mcp), mcp.region ?? ''].filter(Boolean).join(' · ');

  return (
    <Page>
      <Link to="/tool-gateways" className={BACK_LINK}>← Tool gateways</Link>
      <div className="mt-2 mb-5 flex items-center gap-3 min-w-0">
        <AgentAvatar name={mcp.name} size="lg" />
        <div className="min-w-0">
          <h1 className="text-xl font-semibold text-slate-900"><BreakableName name={mcp.name} /></h1>
          {where && <p className="text-sm text-slate-600">{where}</p>}
          <div className="flex flex-wrap items-center gap-1.5 mt-1">
            <Badge cls={state.cls} label={state.label} />
            {chip ? <Badge cls={chip.cls} label={chip.label} title={chip.hint} /> : <Badge cls={kind.cls} label={kind.label} />}
            {mcp.shared && <Badge cls="bg-violet-50 text-violet-700" label="Shared with all tenants" />}
            {/* The version of a gateway no reader read is not known. */}
            {!notRead && <span className="text-xs text-slate-600">v{mcp.version}</span>}
          </div>
        </div>
      </div>

      <TabBar
        tabs={tabs}
        active={active.id}
        label="Tool gateway sections"
        onSelect={(tab) => setSearchParams(tab === tabs[0].id ? {} : { tab }, { replace: true })}
      />

      {notRead ? (
        active.id === 'overview' ? (
          <DetectedOverview mcp={mcp} title={notRead.title} sentence={notRead.sentence} />
        ) : (
          // Tools, Policies and Connected agents: not empty, not readable. Nothing is asked of the API.
          <NoReaderCard title={notRead.title} body={notRead.sentence} more={active.id === 'connected-agents' ? CONNECTED_NOT_KNOWN : undefined} />
        )
      ) : active.id === 'overview' ? (
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

/** A value the detection may not carry, in words when it does not. */
function Recorded({ value }: { value: string | null | undefined }) {
  return value ? <>{value}</> : <span className="text-slate-600">{NOT_RECORDED}</span>;
}

/**
 * The Overview of a gateway no reader read: why, and what the organization registry's detection
 * says. No description, endpoint, tenant, policy engine or version is shown, because none is known.
 */
function DetectedOverview({ mcp, title, sentence }: { mcp: McpServer; title: string; sentence: string }) {
  return (
    <div className="space-y-5">
      <NoReaderCard title={title} body={sentence} />
      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-3">What was detected</h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
          <Field className="sm:col-span-2 lg:col-span-3" label="Gateway ARN"><CodeValue value={mcp.gateway_arn} copyLabel="gateway ARN" /></Field>
          <Field label="Account"><Recorded value={gatewayAccount(mcp)} /></Field>
          <Field label="Region"><Recorded value={mcp.region} /></Field>
          <Field label="Detected by"><Recorded value={gatewayDetectedBy(mcp)} /></Field>
          <Field label="Inbound authorizer"><Recorded value={mcp.authorizer_type ? inboundAuthorizerLabel(mcp.authorizer_type) : ''} /></Field>
          <Field label="Protocol"><Recorded value={mcp.protocol} /></Field>
          <Field label="Detected">{formatDate(knownTime(mcp.created_at), NOT_RECORDED)}</Field>
          <Field label="Gateway id"><span className="font-mono text-xs break-all">{mcp.id}</span></Field>
        </dl>
      </div>
    </div>
  );
}

function OverviewTab({ mcp, tenantName }: { mcp: McpServer; tenantName: string | null }) {
  const endpoint = mcpEndpoint(mcp);
  const tenant = tenantBadge(tenantName ?? mcp.tenant_id);
  const isGateway = mcp.kind === 'gateway' || !!mcp.gateway_arn || !!mcp.gateway_url;
  const account = gatewayAccount(mcp);
  const detectedBy = gatewayDetectedBy(mcp);

  return (
    <div className="space-y-5">
      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-1">Description</h2>
        <p className="text-sm text-slate-700 whitespace-pre-wrap">
          {mcp.description ? mcp.description : <span className="text-slate-600">No description.</span>}
        </p>
      </div>

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-3">Connection</h2>
        <dl className="grid grid-cols-1 lg:grid-cols-2 gap-x-8 gap-y-4">
          <Field className="lg:col-span-2" label={endpoint?.fromGateway ? 'Gateway URL' : 'Endpoint URL'}>
              <CodeValue value={endpoint?.url} copyLabel="endpoint URL" />
            </Field>
          {isGateway && (
            <Field className="lg:col-span-2" label="Gateway ARN"><CodeValue value={mcp.gateway_arn} copyLabel="gateway ARN" /></Field>
          )}
          {mcp.runtime_arn && (
            <Field className="lg:col-span-2" label="Runtime ARN"><CodeValue value={mcp.runtime_arn} copyLabel="runtime ARN" /></Field>
          )}
          {isGateway && <Field label="Cedar enforcement">{policyCell(mcp)}</Field>}
          {isGateway && (
            <Field label="Policy engine">
              {mcp.cedar_policy_engine_id ? (
                <span className="font-mono text-xs break-all">{mcp.cedar_policy_engine_id}</span>
              ) : (
                <span className="text-slate-600">None attached</span>
              )}
            </Field>
          )}
          {mcp.authorizer_type && <Field label="Inbound authorizer">{inboundAuthorizerLabel(mcp.authorizer_type)}</Field>}
          {mcp.protocol && <Field label="Protocol">{mcp.protocol}</Field>}
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
          <Field label="Account">{account || <span className="text-slate-600">{NOT_SET}</span>}</Field>
          <Field label="Region">{mcp.region ?? <span className="text-slate-600">{NOT_SET}</span>}</Field>
          {detectedBy && <Field label="Detected by">{detectedBy}</Field>}
          <Field label="Data classification">{mcp.data_classification ?? <span className="text-slate-600">{NOT_SET}</span>}</Field>
          <Field label="Workload identity">{identityStatusLabel(mcp.identity_status)}</Field>
        </dl>
      </div>

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-800 mb-3">Record</h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
          <Field label="Gateway id"><span className="font-mono text-xs break-all">{mcp.id}</span></Field>
          <Field label="Created by"><MaskedText value={mcp.created_by} /></Field>
          {/* The API sends the epoch for a time it cannot know: that is not a date to show. */}
          <Field label="Created">{formatDate(knownTime(mcp.created_at), NOT_RECORDED)}</Field>
          <Field label="Updated">{formatDate(knownTime(mcp.updated_at), NOT_RECORDED)}</Field>
        </dl>
      </div>
    </div>
  );
}

function ToolsTab({ mcp }: { mcp: McpServer }) {
  const tools = mcp.available_tools ?? [];
  if (tools.length === 0) {
    return <div className={`${CARD} p-8 text-center text-slate-600 text-sm`}>No tools are recorded for this gateway.</div>;
  }
  return (
    <div className="space-y-3">
      <p className="text-[11px] uppercase tracking-wide text-slate-600 font-medium">
        {tools.length} {tools.length === 1 ? 'tool' : 'tools'}
      </p>
      {tools.map((tool, i) => (
        <div key={`${tool.name}-${i}`} className={`${CARD} p-5`}>
          <code className="text-sm font-mono font-semibold text-slate-800 break-all">{tool.name}</code>
          {tool.description && <p className="text-sm text-slate-600 mt-1 whitespace-pre-wrap">{tool.description}</p>}
          <details className="mt-3">
            <summary className="text-[11px] uppercase tracking-wide text-slate-600 font-medium cursor-pointer">Input schema</summary>
            <pre className="mt-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg p-3 overflow-x-auto text-slate-700">
              {JSON.stringify(tool.input_schema ?? {}, null, 2)}
            </pre>
          </details>
        </div>
      ))}
    </div>
  );
}
