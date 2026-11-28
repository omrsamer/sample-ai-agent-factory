// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useState } from 'react';
import { mcpServersApi } from '../../api/client';
import type { CedarPolicyRow, McpServer } from '../../api/client';
import { enforcementView, postureWarning, toEnforcementMode } from './cedarPosture';
import { DataNotes } from './agent-tabs/ObsEmptyCard';
import { maskAccountIds } from '../shared/arnDisplay';
import { Badge, CARD, ErrorCard, Loading, TABLE_HEAD, TD, TH } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

function effectBadge(effect: string): { cls: string; label: string } {
  return effect === 'deny' || effect === 'forbid'
    ? { cls: 'bg-rose-50 text-rose-700', label: 'Forbid' }
    : { cls: 'bg-emerald-50 text-emerald-700', label: 'Permit' };
}

function PolicyRow({ policy }: { policy: CedarPolicyRow }) {
  const [open, setOpen] = useState(false);
  const effect = effectBadge(policy.effect);
  const detailId = `cedar-${policy.policy_id}`;
  return (
    <>
      <tr>
        <td className={`${TD} font-mono text-xs text-slate-700 break-all`}>{policy.policy_id}</td>
        <td className={`${TD} text-slate-600`}>{policy.user_label || policy.user_oid || 'Any authorised caller'}</td>
        <td className={`${TD} text-slate-600`}>{policy.tool || 'All tools'}</td>
        <td className={TD}><Badge cls={effect.cls} label={effect.label} /></td>
        <td className={`${TD} text-slate-600`}>{(policy.conditions ?? []).length || 'None'}</td>
        <td className={`${TD} text-right`}>
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-controls={detailId}
            className="text-xs font-medium text-blue-700 hover:underline"
          >
            {open ? 'Hide Cedar' : 'Show Cedar'}
          </button>
        </td>
      </tr>
      {open && (
        <tr id={detailId}>
          <td colSpan={6} className="px-4 pb-3">
            <pre className="text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg p-3 overflow-x-auto text-slate-700 whitespace-pre-wrap">
              {maskAccountIds(policy.cedar_text)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * Read-only view of a tool gateway's Cedar policies and enforcement mode. Policies are
 * authored as code and applied by the platform pipeline; nothing here changes them.
 */
export default function CedarPoliciesTab({ mcp }: { mcp: McpServer }) {
  const policies = useAsync(() => mcpServersApi.policies(mcp.id), [mcp.id], 'Failed to load policies.');
  const enforcement = useAsync(() => mcpServersApi.policyEnforcement(mcp.id), [mcp.id], 'Failed to read the enforcement mode.');

  // The dedicated read wins; the policy set and the gateway record are fallbacks for it.
  const mode = enforcement.data?.enforcement_mode ?? policies.data?.enforcement_mode ?? mcp.cedar_enforcement_mode;
  const modePending = enforcement.loading && policies.loading && !mcp.cedar_enforcement_mode;
  const banner = enforcementView(mode);
  const warning = postureWarning(mode);
  const rows = policies.data?.policies ?? [];
  // When the mode is not one of the three, the policies were not read either: an empty list
  // then means "not read", and the API's own sentence says why when it sent one.
  const modeKnown = toEnforcementMode(mode) !== null;
  const why = (enforcement.data?.detail ?? '').trim();

  return (
    <div className="space-y-4">
      {modePending ? (
        <Loading label="Reading the enforcement mode…" />
      ) : (
        <div className={`${CARD} ${banner.ring} p-4`} role="status">
          <div className="flex items-center gap-2">
            <span className={`inline-block h-2.5 w-2.5 rounded-full ${banner.dot}`} aria-hidden="true" />
            <h2 className="text-sm font-semibold text-slate-900">{banner.heading}</h2>
          </div>
          <p className="text-sm text-slate-600 mt-1">{!modeKnown && why ? why : banner.body}</p>
          {warning && <p className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mt-3">{warning}</p>}
          <p className="text-xs text-slate-600 mt-3">
            Policies and the enforcement mode are defined as code and applied by the platform pipeline. They cannot be changed from this portal.
          </p>
        </div>
      )}

      <DataNotes notes={policies.data?.warnings ?? []} />

      {policies.loading ? (
        <Loading label="Loading policies…" />
      ) : policies.error ? (
        <ErrorCard title="Couldn’t load policies" message={policies.error} onRetry={policies.reload} />
      ) : rows.length === 0 ? (
        <div className={`${CARD} p-5 text-sm text-slate-600`}>
          {modeKnown ? 'No Cedar policy is attached to this gateway.' : 'The policies of this gateway could not be read.'}
        </div>
      ) : (
        <div className={`${CARD} overflow-x-auto`}>
          <table className="w-full text-sm">
            <thead className={TABLE_HEAD}>
              <tr>
                <th scope="col" className={TH}>Policy id</th>
                <th scope="col" className={TH}>Principal</th>
                <th scope="col" className={TH}>Tool</th>
                <th scope="col" className={TH}>Effect</th>
                <th scope="col" className={TH}>Conditions</th>
                <th scope="col" className={TH}><span className="sr-only">Cedar source</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((p) => <PolicyRow key={p.policy_id} policy={p} />)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
