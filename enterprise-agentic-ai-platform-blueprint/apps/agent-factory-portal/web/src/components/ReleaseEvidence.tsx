// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { agentsApi } from '../api/client';
import EvaluationsTab from './governance/agent-tabs/EvaluationsTab';
import { agentContext, isContained } from './governance/inventory';
import { resolveTenantName } from './governance/tenantUi';
import { useUser } from '../contexts/UserContext';
import { CARD, EmptyCard, ErrorCard, Loading, Page, PageHeader } from './shared/ui';
import { useAsync } from './shared/useAsync';

/**
 * Release evidence by agent: the evaluation runs and gate result behind each build, for
 * approvers and risk reviewers. Read-only; evidence is produced by the pipeline.
 */
export default function ReleaseEvidence() {
  const { agentId } = useParams();
  const navigate = useNavigate();
  const { user } = useUser();
  const agents = useAsync(() => agentsApi.list(), [], 'Failed to load agents.');
  const sorted = useMemo(() => [...(agents.data ?? [])].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id)), [agents.data]);

  return (
    <Page>
      <PageHeader
        title="Release evidence"
        subtitle="The evaluation runs and release-gate result recorded for an agent's builds, including any promotion approved without a passing run."
      />
      {agents.loading ? (
        <Loading label="Loading agents…" />
      ) : agents.error ? (
        <ErrorCard title="Couldn’t load agents" message={agents.error} onRetry={agents.reload} />
      ) : sorted.length === 0 ? (
        <EmptyCard title="No agents yet" body="Release evidence appears once an agent has been built and evaluated by its pipeline." />
      ) : (
        <>
          <div className={`${CARD} p-4 mb-5`}>
            <label htmlFor="evidence-agent" className="block text-[11px] font-medium text-slate-600 uppercase tracking-wide mb-1">
              Agent
            </label>
            <select
              id="evidence-agent"
              value={agentId ?? ''}
              onChange={(e) => navigate(e.target.value ? `/release-evidence/${encodeURIComponent(e.target.value)}` : '/release-evidence')}
              className="w-full max-w-md px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white"
            >
              <option value="">Select an agent…</option>
              {sorted.map((a) => {
                // Two agents can carry one name: the tenant and the account tell them apart.
                const context = agentContext(a, resolveTenantName(a.tenant_id, user?.tenants));
                const label = context ? `${a.name} · ${context}` : a.name;
                return <option key={a.id} value={a.id}>{isContained(a) ? `${label} (contained)` : label}</option>;
              })}
            </select>
          </div>
          {agentId ? (
            <EvaluationsTab key={agentId} agentId={agentId} />
          ) : (
            <EmptyCard title="Select an agent" body="Choose an agent above to see the evidence recorded for its builds." />
          )}
        </>
      )}
    </Page>
  );
}
