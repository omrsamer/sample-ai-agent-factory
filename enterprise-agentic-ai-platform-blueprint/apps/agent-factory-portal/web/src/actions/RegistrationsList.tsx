// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useUser } from '../contexts/UserContext';
import { Badge, CARD, ErrorCard, Page, PageHeader, TABLE_HEAD, TD, TH, formatDate } from '../components/shared/ui';
import { useAsync } from '../components/shared/useAsync';
import { registrationsApi, type RegistrationStatus } from './registrationsClient';
import { PIPELINE_NOTE, STATUS_OPTIONS, authoritiesOf, statusView } from './registrationView';

const PRIMARY = 'px-3.5 py-1.5 rounded-lg bg-blue-700 text-white text-sm font-medium hover:bg-blue-800 shrink-0';

/** Every registration the caller may see, with a status filter. */
export default function RegistrationsList() {
  const { user } = useUser();
  const who = authoritiesOf(user);
  const [status, setStatus] = useState<'all' | RegistrationStatus>('all');
  const { data, loading, error, reload } = useAsync(
    () => registrationsApi.list(status === 'all' ? undefined : { status }),
    [status],
    'Failed to load registrations.',
  );
  const rows = data ?? [];

  return (
    <Page>
      <PageHeader title="Registrations" subtitle={PIPELINE_NOTE}>
        {who.registrar && (
          <Link to="/registrations/new" className={PRIMARY}>
            Register agent
          </Link>
        )}
      </PageHeader>

      <div className={`${CARD} p-2.5 mb-3 max-w-xs`}>
        <label htmlFor="registration-status" className="sr-only">Filter by status</label>
        <select
          id="registration-status"
          className="w-full px-3 py-1.5 text-sm rounded-lg border border-slate-300 bg-white"
          value={status}
          onChange={(e) => setStatus(e.target.value as 'all' | RegistrationStatus)}
        >
          <option value="all">All statuses</option>
          {STATUS_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      </div>

      {error ? (
        <ErrorCard title="Couldn’t load registrations" message={error} onRetry={reload} />
      ) : (
        <div className={`${CARD} overflow-x-auto`}>
          <table className="w-full text-sm">
            <thead className={TABLE_HEAD}>
              <tr>
                <th scope="col" className={TH}>Agent</th>
                <th scope="col" className={TH}>Tenant</th>
                <th scope="col" className={TH}>Environment</th>
                <th scope="col" className={TH}>Status</th>
                <th scope="col" className={TH}>Version</th>
                <th scope="col" className={TH}>Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-600 text-sm" role="status">Loading registrations…</td>
                </tr>
              )}
              {!loading && rows.map((r) => {
                const view = statusView(r.status);
                return (
                  <tr key={r.record_id}>
                    <td className={TD}>
                      <Link to={`/registrations/${encodeURIComponent(r.record_id)}`} className="font-medium text-blue-700 hover:underline break-all">
                        {r.agent_id || r.name || r.record_id}
                      </Link>
                    </td>
                    <td className={`${TD} text-slate-600`}>{r.tenant_id || '—'}</td>
                    <td className={`${TD} text-slate-600`}>{r.environment || '—'}</td>
                    <td className={TD}><Badge cls={view.cls} label={view.label} /></td>
                    <td className={`${TD} text-slate-600`}>{r.record_version || '—'}</td>
                    <td className={`${TD} text-slate-600 whitespace-nowrap`}>{formatDate(r.updated_at)}</td>
                  </tr>
                );
              })}
              {!loading && rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-600 text-sm">
                    {status === 'all' ? 'No registrations yet.' : 'No registrations with this status.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}
