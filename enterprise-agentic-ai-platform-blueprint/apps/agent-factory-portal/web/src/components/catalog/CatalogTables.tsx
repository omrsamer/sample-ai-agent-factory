// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { catalogApi } from '../../api/client';
import { Badge, CARD, CodeValue, EmptyCard, ErrorCard, Loading, TABLE_HEAD, TD, TH } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

const STATUS_CLS: Record<string, string> = {
  approved: 'bg-emerald-50 text-emerald-700',
  active: 'bg-emerald-50 text-emerald-700',
  restricted: 'bg-amber-50 text-amber-700',
  pending: 'bg-amber-50 text-amber-700',
  deprecated: 'bg-slate-100 text-slate-500',
  blocked: 'bg-red-50 text-red-700',
};

/** Status values are rendered as recorded; only the colour is derived. */
function statusCls(status: string): string {
  const key = status.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(STATUS_CLS, key) ? STATUS_CLS[key] : 'bg-slate-100 text-slate-600';
}

/** Foundation models approved for use. Read-only. */
export function CatalogModels() {
  const { data, loading, error, reload } = useAsync(() => catalogApi.models(), [], 'Failed to load models.');
  if (loading) return <Loading label="Loading models…" />;
  if (error) return <ErrorCard title="Couldn’t load models" message={error} onRetry={reload} />;
  const rows = data ?? [];
  if (rows.length === 0) return <EmptyCard title="No models in the catalog" body="Approved models appear here once the platform baseline lists them." />;
  return (
    <div className={`${CARD} overflow-x-auto`}>
      <table className="w-full text-sm">
        <thead className={TABLE_HEAD}>
          <tr>
            <th scope="col" className={TH}>Model id</th>
            <th scope="col" className={TH}>Provider</th>
            <th scope="col" className={TH}>Regions</th>
            <th scope="col" className={TH}>Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((m) => (
            <tr key={m.model_id}>
              <td className={`${TD} font-mono text-xs text-slate-800 break-all`}>{m.model_id}</td>
              <td className={`${TD} text-slate-600`}>{m.provider}</td>
              <td className={`${TD} text-slate-600`}>{(m.regions ?? []).join(', ') || '—'}</td>
              <td className={TD}><Badge cls={statusCls(m.status)} label={m.status} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Tool records in the registry. Read-only. */
export function CatalogTools() {
  const { data, loading, error, reload } = useAsync(() => catalogApi.tools(), [], 'Failed to load tools.');
  if (loading) return <Loading label="Loading tools…" />;
  if (error) return <ErrorCard title="Couldn’t load tools" message={error} onRetry={reload} />;
  const rows = data ?? [];
  if (rows.length === 0) return <EmptyCard title="No tools in the registry" body="Tools appear here once a team has published one through the tool catalogue pipeline." />;
  return (
    <div className={`${CARD} overflow-x-auto`}>
      <table className="w-full text-sm">
        <thead className={TABLE_HEAD}>
          <tr>
            <th scope="col" className={TH}>Tool</th>
            <th scope="col" className={TH}>Owner</th>
            <th scope="col" className={TH}>Cost centre</th>
            <th scope="col" className={TH}>Version</th>
            <th scope="col" className={TH}>Status</th>
            <th scope="col" className={TH}>Target</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((t) => (
            <tr key={t.tool_id} className="align-top">
              <td className={TD}>
                <div className="font-medium text-slate-800">{t.name}</div>
                {t.description && <div className="text-xs text-slate-500 mt-0.5 max-w-md">{t.description}</div>}
                <div className="text-[11px] font-mono text-slate-400 mt-0.5 break-all">{t.tool_id}</div>
              </td>
              <td className={`${TD} text-slate-600`}>{t.owner || '—'}</td>
              <td className={`${TD} text-slate-600`}>{t.cost_centre || '—'}</td>
              <td className={`${TD} text-slate-600`}>{t.version || '—'}</td>
              <td className={TD}><Badge cls={statusCls(t.status)} label={t.status} /></td>
              <td className={TD}><CodeValue value={t.target_arn} copyLabel="target ARN" /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
