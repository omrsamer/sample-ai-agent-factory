// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Link } from 'react-router-dom';
import { BreakableName } from '../components/governance/agentUi';
import { useUser } from '../contexts/UserContext';
import { Badge, CARD, EmptyCard, ErrorCard, Loading, Page, PageHeader, TABLE_HEAD, TD, TH, formatDate } from '../components/shared/ui';
import { useAsync } from '../components/shared/useAsync';
import { registrationsApi, type RegistrationDetail } from './registrationsClient';
import { OWN_SUBMISSION_NOTE, authoritiesOf } from './registrationView';

/**
 * The approval queue: records waiting for a decision. Each opens the record's page, which shows
 * the full document, the changes since the last approved version, and the decision controls.
 */
export default function Approvals() {
  const { user, isLoading } = useUser();
  const who = authoritiesOf(user);
  const queue = useAsync<RegistrationDetail[]>(
    async () => {
      if (!who.approver) return [];
      const pending = await registrationsApi.list({ status: 'PENDING_APPROVAL' });
      // The list does not say who submitted a record; the record itself does.
      const details = await Promise.allSettled(pending.map((r) => registrationsApi.get(r.record_id)));
      return pending.map((r, i) => {
        const detail = details[i];
        return detail.status === 'fulfilled' ? detail.value : r;
      });
    },
    [who.approver],
    'Failed to load the approval queue.',
  );

  return (
    <Page>
      <PageHeader
        title="Approvals"
        subtitle="Registrations waiting for a decision. Approving a record records a decision; deployment still happens only through the Workload pipeline."
      />
      {isLoading || queue.loading ? (
        <Loading label="Loading the approval queue…" />
      ) : !who.approver ? (
        <ErrorCard title="You do not hold the authority for this action" message="Seeing the approval queue needs the approver authority." />
      ) : queue.error ? (
        <ErrorCard title="Couldn’t load the approval queue" message={queue.error} onRetry={queue.reload} />
      ) : (queue.data ?? []).length === 0 ? (
        <EmptyCard title="Nothing is waiting for approval" body="Records appear here once a registrar submits them." />
      ) : (
        <div className={`${CARD} overflow-x-auto`}>
          <table className="w-full text-sm">
            <thead className={TABLE_HEAD}>
              <tr>
                <th scope="col" className={TH}>Agent</th>
                <th scope="col" className={TH}>Tenant</th>
                <th scope="col" className={TH}>Environment</th>
                <th scope="col" className={TH}>Risk class</th>
                <th scope="col" className={TH}>Submitted by</th>
                <th scope="col" className={TH}>Submitted</th>
                <th scope="col" className={TH}><span className="sr-only">Review</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {(queue.data ?? []).map((r) => (
                <tr key={r.record_id}>
                  <td className={`${TD} font-medium text-slate-800`}><BreakableName name={r.agent_id || r.name || r.record_id} /></td>
                  <td className={`${TD} text-slate-600`}>{r.tenant_id || 'None'}</td>
                  <td className={`${TD} text-slate-600`}>{r.environment || 'Not set'}</td>
                  <td className={`${TD} text-slate-600`}>{typeof r.document?.risk_class === 'string' ? r.document.risk_class : 'Not set'}</td>
                  <td className={`${TD} text-slate-600`}>
                    {r.submitted_by_label || 'Not recorded'}
                    {r.submitted_by_me && <Badge cls="ml-2 bg-slate-100 text-slate-700" label="You" title={OWN_SUBMISSION_NOTE} />}
                  </td>
                  <td className={`${TD} text-slate-600 whitespace-nowrap`}>{formatDate(r.submitted_at)}</td>
                  <td className={`${TD} text-right`}>
                    <Link
                      to={`/registrations/${encodeURIComponent(r.record_id)}`}
                      className="text-sm font-medium text-blue-700 hover:underline"
                      aria-label={`Review ${r.agent_id || r.name || r.record_id}`}
                    >
                      Review
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}
