// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState } from 'react';
import { agentOpsApi, isNotFound } from '../../../api/client';
import type { Agent } from '../../../api/client';
import { platformLabel } from '../platformLabels';
import { Badge, CARD, CodeValue, ErrorCard, Field, Loading, TABLE_HEAD, TD, TH, formatDate } from '../../shared/ui';
import { useAsync } from '../../shared/useAsync';
import { agentEnvironments, deploymentActor, outcomeBadge, runtimeStatusBadge, shortSha } from './deploymentView';

const HISTORY_LIMIT = 25;

/** Runtime status and deployment history for one agent. Deployments are made by its pipeline. */
export default function DeploymentTab({ agent }: { agent: Agent }) {
  const environments = agentEnvironments(agent.agent_arns);
  const [environment, setEnvironment] = useState<string>('');
  const stage = environment || undefined;

  const runtime = useAsync(() => agentOpsApi.runtime(agent.id, { stage }), [agent.id, stage], 'Failed to read runtime status.');
  const history = useAsync(
    () => agentOpsApi.deployments(agent.id, { stage, limit: HISTORY_LIMIT }),
    [agent.id, stage],
    'Failed to load deployment history.',
  );
  const status = runtimeStatusBadge(runtime.data?.status);
  // Filtered here as well, so the list is right even if the API ignores the `stage` filter.
  const rows = (history.data ?? []).filter((row) => !stage || row.stage === stage);
  const otherEnvironment = stage && runtime.data?.stage && runtime.data.stage !== stage ? runtime.data.stage : null;

  return (
    <div className="space-y-5">
      <div className={`${CARD} p-5`}>
        <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-800">Runtime</h2>
            <p className="text-xs text-slate-600 mt-0.5">Deployed by the Workstream pipeline. This portal does not start, stop or change a runtime.</p>
          </div>
          {environments.length > 1 && (
            <div>
              <label htmlFor="deployment-environment" className="sr-only">Environment</label>
              <select
                id="deployment-environment"
                value={environment}
                onChange={(e) => setEnvironment(e.target.value)}
                className="px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white"
              >
                <option value="">Latest deployed</option>
                {environments.map((env) => (
                  <option key={env} value={env}>{env}</option>
                ))}
              </select>
            </div>
          )}
        </div>
        {runtime.loading ? (
          <Loading label="Reading runtime status…" />
        ) : runtime.error ? (
          <p className="text-sm text-slate-600">Runtime status is unavailable. {isNotFound(runtime.cause) ? 'No runtime is recorded for this agent.' : runtime.error}</p>
        ) : (
          <>
          {otherEnvironment && (
            <p className="mb-4 text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2" role="status">
              A reading for {stage} is not available. This is the status of {otherEnvironment}.
            </p>
          )}
          <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
            <Field label="Status"><Badge cls={status.cls} label={status.label} title={runtime.data?.detail ?? undefined} /></Field>
            <Field label="Environment">{runtime.data?.stage || 'Not set'}</Field>
            <Field label="Image tag"><span className="font-mono text-xs break-all">{runtime.data?.image_tag || 'Not set'}</span></Field>
            <Field label="Platform">{platformLabel(agent.platform)}</Field>
            <Field label="Region">{agent.region ?? 'Not set'}</Field>
            <Field label="Checked">{formatDate(runtime.data?.checked_at)}</Field>
            <Field className="sm:col-span-2 lg:col-span-3" label="Runtime ARN"><CodeValue value={runtime.data?.runtime_arn} copyLabel="runtime ARN" /></Field>
            {runtime.data?.detail && (
              <Field className="sm:col-span-2 lg:col-span-3" label="Detail">{runtime.data.detail}</Field>
            )}
          </dl>
          </>
        )}
      </div>

      <section aria-labelledby="deployment-history-heading">
        <h2 id="deployment-history-heading" className="text-sm font-semibold text-slate-800 mb-2">Deployment history</h2>
        {history.loading ? (
          <Loading label="Loading deployment history…" />
        ) : history.error ? (
          <ErrorCard title="Couldn’t load deployment history" message={history.error} onRetry={history.reload} />
        ) : rows.length === 0 ? (
          <div className={`${CARD} p-5 text-sm text-slate-600`}>{stage ? `No deployment has been recorded for ${stage}.` : 'No deployment has been recorded for this agent.'}</div>
        ) : (
          <div className={`${CARD} overflow-x-auto`}>
            <table className="w-full text-sm">
              <thead className={TABLE_HEAD}>
                <tr>
                  <th scope="col" className={TH}>Started</th>
                  <th scope="col" className={TH}>Environment</th>
                  <th scope="col" className={TH}>Image tag</th>
                  <th scope="col" className={TH}>Commit</th>
                  <th scope="col" className={TH}>Outcome</th>
                  <th scope="col" className={TH}>Started by</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {rows.map((row) => {
                  const outcome = outcomeBadge(row.outcome);
                  return (
                    <tr key={row.id}>
                      <td className={`${TD} text-slate-700 whitespace-nowrap`}>{formatDate(row.started_at)}</td>
                      <td className={`${TD} text-slate-600`}>{row.stage}</td>
                      <td className={`${TD} font-mono text-xs text-slate-700 break-all`}>{row.image_tag}</td>
                      <td className={`${TD} font-mono text-xs text-slate-600`} title={row.source_sha ?? undefined}>{shortSha(row.source_sha)}</td>
                      <td className={TD}><Badge cls={outcome.cls} label={outcome.label} title={row.error ?? undefined} /></td>
                      <td className={`${TD} text-slate-600`}>{deploymentActor(row)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
