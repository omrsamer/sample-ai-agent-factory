// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { agentMcpGrantsApi } from '../../api/client';
import type { Agent } from '../../api/client';
import { computeDrift, type DriftState } from './mcpDrift';
import { Badge, CARD, ErrorCard, Loading, TABLE_HEAD, TD, TH } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

const STATE_VIEW: Record<DriftState, { label: string; cls: string; hint: string }> = {
  connected: { label: 'Subscribed', cls: 'bg-emerald-50 text-emerald-700', hint: 'Declared by the agent and subscribed.' },
  not_granted: {
    label: 'Declared, not subscribed',
    cls: 'bg-amber-50 text-amber-700',
    hint: 'The agent descriptor names this gateway but no subscription exists, so calls to it are refused.',
  },
  unused_grant: {
    label: 'Subscribed, not declared',
    cls: 'bg-slate-100 text-slate-600',
    hint: 'A subscription exists that the agent descriptor does not name.',
  },
};

/** The tool gateways an agent may call, compared with the ones its descriptor declares. */
export default function AgentToolSubscriptionsTab({ agent }: { agent: Agent }) {
  const { data, loading, error, reload } = useAsync(
    () => agentMcpGrantsApi.list(agent.id),
    [agent.id],
    'Failed to load tool subscriptions.',
  );

  const rows = useMemo(() => {
    const grants = data ?? [];
    const byId = new Map(grants.map((g) => [g.mcp_id, g]));
    return computeDrift(agent.declared_mcp_server_ids, grants.map((g) => g.mcp_id)).map((row) => ({
      ...row,
      name: byId.get(row.id)?.mcp_name ?? row.id,
      role: byId.get(row.id)?.role ?? 'Not set',
    }));
  }, [data, agent.declared_mcp_server_ids]);

  return (
    <div className="space-y-4">
      <div className={`${CARD} p-4 text-sm text-slate-600`}>
        Tool subscriptions come from the agent descriptor and are applied by its pipeline; they cannot be edited here.
        In the default profile a tool gateway authorises the calling workload with AWS IAM, so a subscription is granted
        to the agent, not to individual end users.
      </div>
      {loading ? (
        <Loading label="Loading tool subscriptions…" />
      ) : error ? (
        <ErrorCard title="Couldn’t load tool subscriptions" message={error} onRetry={reload} />
      ) : rows.length === 0 ? (
        <div className={`${CARD} p-5 text-sm text-slate-600`}>This agent is not subscribed to any tool gateway.</div>
      ) : (
        <div className={`${CARD} overflow-x-auto`}>
          <table className="w-full text-sm">
            <thead className={TABLE_HEAD}>
              <tr>
                <th scope="col" className={TH}>Tool gateway</th>
                <th scope="col" className={TH}>Role</th>
                <th scope="col" className={TH}>State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((row) => {
                const view = STATE_VIEW[row.state];
                return (
                  <tr key={row.id}>
                    <td className={TD}>
                      <Link to={`/tool-gateways/${encodeURIComponent(row.id)}`} className="font-medium text-blue-700 hover:underline">
                        {row.name}
                      </Link>
                    </td>
                    <td className={`${TD} text-slate-600`}>{row.role}</td>
                    <td className={TD}>
                      <Badge cls={view.cls} label={view.label} title={view.hint} />
                      <span className="sr-only"> {view.hint}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
