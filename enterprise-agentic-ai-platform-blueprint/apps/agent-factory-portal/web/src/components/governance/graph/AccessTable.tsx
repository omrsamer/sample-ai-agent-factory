// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { FlowEdge, FlowNode } from './layout';

const TYPE_LABEL: Record<FlowNode['data']['nodeType'], string> = {
  user: 'User',
  group: 'Group',
  agent: 'Agent',
  mcp: 'Tool gateway',
};

const TH = 'text-left font-medium px-4 py-2';
const TD = 'px-4 py-2';
const DETAILS = 'text-xs font-medium text-blue-700 hover:underline';
const HEAD = 'bg-slate-50/80 text-slate-600 text-xs uppercase tracking-wide';
const CARD = 'bg-white/70 backdrop-blur rounded-xl border border-slate-200/60 shadow-sm overflow-x-auto';

/**
 * The access graph as two tables: every relationship, then every node. It carries the same
 * information as the drawing and opens the same detail panel, so the screen is fully usable
 * from the keyboard and by a screen reader.
 */
export default function AccessTable({
  nodes,
  edges,
  onSelectNode,
  onSelectEdge,
}: {
  nodes: FlowNode[];
  edges: FlowEdge[];
  onSelectNode: (id: string) => void;
  onSelectEdge: (id: string) => void;
}) {
  const label = new Map(nodes.map((n) => [n.id, n.data.label]));
  return (
    <div className="space-y-6 overflow-y-auto h-full pr-1">
      <section aria-labelledby="access-relationships">
        <h2 id="access-relationships" className="text-sm font-semibold text-slate-800 mb-2">Relationships</h2>
        {edges.length === 0 ? (
          <p className="text-sm text-slate-600">No relationships to list.</p>
        ) : (
          <div className={CARD}>
            <table className="w-full text-sm">
              <thead className={HEAD}>
                <tr>
                  <th scope="col" className={TH}>From</th>
                  <th scope="col" className={TH}>Relationship</th>
                  <th scope="col" className={TH}>To</th>
                  <th scope="col" className={TH}>Role</th>
                  <th scope="col" className={TH}>Cedar policy</th>
                  <th scope="col" className={TH}><span className="sr-only">Details</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {edges.map((e) => {
                  const from = label.get(e.source) ?? e.source;
                  const to = label.get(e.target) ?? e.target;
                  return (
                    <tr key={e.id}>
                      <td className={`${TD} text-slate-700 break-words`}>{from}</td>
                      <td className={`${TD} text-slate-600`}>{e.data?.edgeType === 'can_call' ? 'can call' : 'has access to'}</td>
                      <td className={`${TD} text-slate-700 break-words`}>{to}</td>
                      <td className={`${TD} text-slate-600`}>{e.data?.role || '—'}</td>
                      <td className={`${TD} text-slate-600`}>{e.data?.hasPolicy ? 'Enforced' : '—'}</td>
                      <td className={`${TD} text-right`}>
                        <button type="button" className={DETAILS} onClick={() => onSelectEdge(e.id)} aria-label={`Details of ${from} to ${to}`}>
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section aria-labelledby="access-nodes">
        <h2 id="access-nodes" className="text-sm font-semibold text-slate-800 mb-2">Principals, agents and tool gateways</h2>
        <div className={CARD}>
          <table className="w-full text-sm">
            <thead className={HEAD}>
              <tr>
                <th scope="col" className={TH}>Name</th>
                <th scope="col" className={TH}>Type</th>
                <th scope="col" className={TH}><span className="sr-only">Details</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {nodes.map((n) => (
                <tr key={n.id}>
                  <td className={`${TD} text-slate-700 break-words`}>{n.data.label}</td>
                  <td className={`${TD} text-slate-600`}>{TYPE_LABEL[n.data.nodeType]}</td>
                  <td className={`${TD} text-right`}>
                    <button type="button" className={DETAILS} onClick={() => onSelectNode(n.id)} aria-label={`Details of ${n.data.label}`}>
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
