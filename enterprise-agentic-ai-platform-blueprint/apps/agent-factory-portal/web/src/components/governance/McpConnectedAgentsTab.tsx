// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { agentsApi, mcpServersApi } from '../../api/client';
import type { McpServer } from '../../api/client';
import { Badge, CARD, ErrorCard, Loading, TABLE_HEAD, TD, TH } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

/** The agents subscribed to a tool gateway. Read-only. */
export default function McpConnectedAgentsTab({ mcp }: { mcp: McpServer }) {
  const grants = useAsync(() => mcpServersApi.connectedAgents(mcp.id), [mcp.id], 'Failed to load connected agents.');
  // Used only to turn a connection into a link; the table still renders if this read fails.
  const agents = useAsync(() => agentsApi.list(), [], 'Failed to load agents.');

  const linkFor = useMemo(() => {
    const byWorkloadId = new Map<string, string>();
    for (const a of agents.data ?? []) {
      byWorkloadId.set(a.id, a.id);
      if (a.entra_sp_id) byWorkloadId.set(a.entra_sp_id, a.id);
    }
    return (principalId: string) => byWorkloadId.get(principalId) ?? null;
  }, [agents.data]);

  if (grants.loading) return <Loading label="Loading connected agents…" />;
  if (grants.error) return <ErrorCard title="Couldn’t load connected agents" message={grants.error} onRetry={grants.reload} />;
  const rows = grants.data ?? [];
  if (rows.length === 0) {
    return <div className={`${CARD} p-5 text-sm text-slate-500`}>No agent is subscribed to this gateway.</div>;
  }

  return (
    <div className={`${CARD} overflow-x-auto`}>
      <table className="w-full text-sm">
        <thead className={TABLE_HEAD}>
          <tr>
            <th scope="col" className={TH}>Agent</th>
            <th scope="col" className={TH}>Role</th>
            <th scope="col" className={TH}>Subscription id</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((g) => {
            const agentId = linkFor(g.principal_id);
            return (
              <tr key={g.assignment_id}>
                <td className={TD}>
                  {agentId ? (
                    <Link to={`/agents/${encodeURIComponent(agentId)}`} className="font-medium text-blue-700 hover:underline">
                      {g.principal_display || g.principal_id}
                    </Link>
                  ) : (
                    <span className="text-slate-700">{g.principal_display || g.principal_id}</span>
                  )}
                </td>
                <td className={TD}><Badge cls="bg-slate-100 text-slate-600" label={g.role} /></td>
                <td className={`${TD} font-mono text-xs text-slate-500 break-all`}>{g.assignment_id}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
