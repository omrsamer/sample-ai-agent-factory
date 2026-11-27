// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { isNotFound } from '../api/client';
import { useUser } from '../contexts/UserContext';
import { Badge, CARD, CodeValue, ErrorCard, Field, Loading, Page, TABLE_HEAD, TD, TH, formatDate } from '../components/shared/ui';
import { useAsync } from '../components/shared/useAsync';
import ActionFailurePanel from './ActionFailurePanel';
import { documentDiff, draftFromDocument, FIELD_LABEL } from './governanceSchema';
import { classifyFailure, registrationsApi, type ActionFailure, type ActionResult, type RegistrationDetail as RegistrationRecord } from './registrationsClient';
import {
  AUDIT_INCOMPLETE_NOTE,
  PIPELINE_NOTE,
  RETURNS_TO_DRAFT_NOTE,
  authoritiesOf,
  historyActionLabel,
  historyRows,
  offeredActions,
  outcomeView,
  statusView,
} from './registrationView';

const PRIMARY = 'px-3.5 py-1.5 rounded-lg bg-blue-700 text-white text-sm font-medium hover:bg-blue-800 disabled:opacity-50';
const SECONDARY = 'px-3.5 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 text-sm font-medium hover:bg-slate-50 disabled:opacity-50';
const DANGER = 'px-3.5 py-1.5 rounded-lg bg-red-700 text-white text-sm font-medium hover:bg-red-800 disabled:opacity-50';
const APPROVE = 'px-3.5 py-1.5 rounded-lg bg-emerald-700 text-white text-sm font-medium hover:bg-emerald-800 disabled:opacity-50';

function DocumentView({ record }: { record: RegistrationRecord }) {
  const d = draftFromDocument(record.document);
  const plain = (value: string) => value || '—';
  return (
    <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
      <Field label={FIELD_LABEL.tenantId}>{plain(d.tenantId)}</Field>
      <Field label={FIELD_LABEL.agentId}><span className="break-all">{plain(d.agentId)}</span></Field>
      <Field label={FIELD_LABEL.environment}>{plain(d.environment)}</Field>
      <Field label={FIELD_LABEL.ownerGroup}><span className="break-words">{plain(d.ownerGroup)}</span></Field>
      <Field label={FIELD_LABEL.contact}><span className="break-all">{plain(d.contact)}</span></Field>
      <Field label={FIELD_LABEL.costCentre}>{plain(d.costCentre)}</Field>
      <Field label={FIELD_LABEL.riskClass}>{plain(d.riskClass)}</Field>
      <Field label={FIELD_LABEL.dataClassification}>{plain(d.dataClassification)}</Field>
      <Field label={FIELD_LABEL.applicationId}><span className="break-all">{plain(d.applicationId)}</span></Field>
      <Field label={FIELD_LABEL.framework}>{plain(d.framework)}</Field>
      <Field label="Golden path">{d.goldenPathName ? `${d.goldenPathName} ${d.goldenPathVersion}` : '—'}</Field>
      <Field label={FIELD_LABEL.recordVersion}>{plain(d.recordVersion)}</Field>
      <Field className="sm:col-span-2 lg:col-span-3" label={FIELD_LABEL.businessPurpose}><span className="whitespace-pre-wrap break-words">{plain(d.businessPurpose)}</span></Field>
      <Field className="sm:col-span-2 lg:col-span-3" label={FIELD_LABEL.runtimeArn}><CodeValue value={d.runtimeArn} copyLabel="runtime ARN" /></Field>
      <Field className="sm:col-span-2 lg:col-span-3" label={FIELD_LABEL.gatewayArn}><CodeValue value={d.gatewayArn} copyLabel="tool gateway ARN" /></Field>
      <Field className="sm:col-span-2 lg:col-span-3" label={FIELD_LABEL.subscribedToolIds}>
          {d.subscribedToolIds.length === 0 ? '—' : <span className="font-mono text-xs break-all">{d.subscribedToolIds.join(', ')}</span>}
        </Field>
    </dl>
  );
}

function DiffView({ record }: { record: RegistrationRecord }) {
  if (!record.previous_approved) return null;
  const rows = documentDiff(record.previous_approved, record.document);
  // An approved, unchanged record equals its approved version; saying so is only useful to
  // someone about to decide.
  if (rows.length === 0 && record.status !== 'PENDING_APPROVAL') return null;
  return (
    <section aria-labelledby="registration-diff" className={`${CARD} p-5`}>
      <h2 id="registration-diff" className="text-sm font-semibold text-slate-900 mb-3">Changes since the last approved version</h2>
      {rows.length === 0 ? (
        <p className="text-sm text-slate-600">Nothing differs from the last approved version, apart from the record version.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className={TABLE_HEAD}>
              <tr>
                <th scope="col" className={TH}>Field</th>
                <th scope="col" className={TH}>Approved</th>
                <th scope="col" className={TH}>Proposed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((row) => (
                <tr key={row.field} className="align-top">
                  <th scope="row" className={`${TD} text-left font-medium text-slate-700 whitespace-nowrap`}>{row.label}</th>
                  <td className={`${TD} text-slate-600 break-all`}>{row.before || 'Not set'}</td>
                  <td className={`${TD} text-slate-900 break-all`}>{row.after || 'Removed'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function History({ recordId, refreshKey }: { recordId: string; refreshKey: number }) {
  const { data, loading, error, cause, reload } = useAsync(() => registrationsApi.history(recordId), [recordId, refreshKey], 'Failed to load the history.');
  const rows = historyRows(data?.events);
  return (
    <section aria-labelledby="registration-history">
      <h2 id="registration-history" className="text-sm font-semibold text-slate-900 mb-2">History</h2>
      {loading ? (
        <Loading label="Loading the history…" />
      ) : error && !isNotFound(cause) ? (
        <ErrorCard title="Couldn’t load the history" message={error} onRetry={reload} />
      ) : rows.length === 0 ? (
        <div className={`${CARD} p-5 text-sm text-slate-600`}>
          No action on this record has been recorded through the portal. A record published by a pipeline has no entries here.
        </div>
      ) : (
        <div className={`${CARD} overflow-x-auto`}>
          <table className="w-full text-sm">
            <thead className={TABLE_HEAD}>
              <tr>
                <th scope="col" className={TH}>When</th>
                <th scope="col" className={TH}>Who</th>
                <th scope="col" className={TH}>Action</th>
                <th scope="col" className={TH}>Outcome</th>
                <th scope="col" className={TH}>Status</th>
                <th scope="col" className={TH}>Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((row) => {
                const outcome = outcomeView(row.outcome);
                return (
                  <tr key={row.key} className="align-top">
                    <td className={`${TD} text-slate-700 whitespace-nowrap`}>{formatDate(row.at)}</td>
                    <td className={`${TD} text-slate-700 break-words`}>
                      {row.actor || '—'}
                      {row.role && <span className="block text-xs text-slate-600">{row.role}</span>}
                    </td>
                    <td className={`${TD} text-slate-700`}>{historyActionLabel(row.action)}</td>
                    <td className={TD}><Badge cls={outcome.cls} label={outcome.label} /></td>
                    <td className={`${TD} text-slate-600 whitespace-nowrap`}>{row.statusChange || '—'}</td>
                    <td className={`${TD} text-slate-600 break-words`}>{row.reason || '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** One registration: its document, what changed, the actions the caller may take, and its history. */
export default function RegistrationDetail() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const { user } = useUser();
  const who = authoritiesOf(user);
  const { data: record, loading, error, cause, reload } = useAsync(() => registrationsApi.get(id), [id], 'Failed to load the registration.');
  const [failure, setFailure] = useState<ActionFailure | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [reason, setReason] = useState('');
  const [reasonError, setReasonError] = useState('');
  const [historyKey, setHistoryKey] = useState(0);
  const [auditGap, setAuditGap] = useState<string | null>(null);

  const refresh = () => {
    setFailure(null);
    setConfirmingDelete(false);
    reload();
    setHistoryKey((k) => k + 1);
  };

  const run = async (action: () => Promise<ActionResult>, fallback: string, after?: () => void) => {
    setBusy(true);
    setFailure(null);
    setAuditGap(null);
    try {
      const result = await action();
      if (result?.audit_complete === false) setAuditGap(result.request_id);
      if (after) after();
      else refresh();
    } catch (err) {
      setFailure(classifyFailure(err, fallback));
      // A refused attempt is recorded by the server, so the history is read again.
      setHistoryKey((k) => k + 1);
    } finally {
      setBusy(false);
    }
  };

  const decide = (decision: 'approve' | 'reject') => {
    const trimmed = reason.trim();
    if (!trimmed) {
      setReasonError('A reason is required.');
      return;
    }
    setReasonError('');
    void run(
      () =>
        decision === 'approve'
          ? registrationsApi.approve(id, trimmed, record?.document_sha256 ?? '')
          : registrationsApi.reject(id, trimmed, record?.document_sha256 ?? ''),
      decision === 'approve' ? 'The record could not be approved' : 'The record could not be rejected',
      () => {
        setReason('');
        refresh();
      },
    );
  };

  if (loading) {
    return (
      <Page>
        <Loading label="Loading the registration…" />
      </Page>
    );
  }
  if (isNotFound(cause)) {
    return (
      <Page>
        <p className="text-sm text-slate-600">
          This registration was not found. <Link to="/registrations" className="text-blue-700 hover:underline">Back to registrations</Link>.
        </p>
      </Page>
    );
  }
  if (error || !record) {
    return (
      <Page>
        <ErrorCard title="Couldn’t load the registration" message={error ?? 'No data was returned.'} onRetry={reload} />
      </Page>
    );
  }

  const offered = offeredActions(record, who);
  const status = statusView(record.status);
  const editPath = `/registrations/${encodeURIComponent(record.record_id)}/edit`;

  return (
    <Page>
      <Link to="/registrations" className="text-xs text-slate-600 hover:text-slate-800">← Registrations</Link>
      <div className="mt-2 mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold text-slate-900 break-all">{record.agent_id || record.name || record.record_id}</h1>
          <div className="flex flex-wrap items-center gap-2 mt-1 text-xs text-slate-600">
            <Badge cls={status.cls} label={status.label} />
            <span>
              Created{record.created_by_label ? ` by ${record.created_by_label}` : ''} · {formatDate(record.created_at)}
            </span>
            {record.submitted_at && (
              <span>
                Submitted{record.submitted_by_label ? ` by ${record.submitted_by_label}` : ''} · {formatDate(record.submitted_at)}
              </span>
            )}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {offered.edit && <Link to={editPath} className={SECONDARY}>Edit</Link>}
          {offered.submit && (
            <button type="button" className={PRIMARY} disabled={busy} onClick={() => void run(() => registrationsApi.submit(id), 'The record could not be submitted')}>
              Submit for approval
            </button>
          )}
          {offered.remove && !confirmingDelete && (
            <button type="button" className={SECONDARY} disabled={busy} onClick={() => setConfirmingDelete(true)}>
              Delete record
            </button>
          )}
        </div>
      </div>

      <div className="space-y-5">
        <p className="text-sm text-slate-700 bg-slate-100 rounded-lg px-3 py-2">{PIPELINE_NOTE}</p>

        {confirmingDelete && (
          <div className="rounded-xl border border-red-200 bg-red-50 p-4" role="group" aria-labelledby="delete-title">
            <p id="delete-title" className="text-sm font-semibold text-red-800">Delete this record? This cannot be undone.</p>
            <div className="flex gap-2 mt-3">
              <button
                type="button"
                className={DANGER}
                disabled={busy}
                onClick={() => void run(() => registrationsApi.remove(id), 'The record could not be deleted', () => navigate('/registrations'))}
              >
                Delete record
              </button>
              <button type="button" className={SECONDARY} disabled={busy} onClick={() => setConfirmingDelete(false)}>
                Keep record
              </button>
            </div>
          </div>
        )}

        <ActionFailurePanel failure={failure} onRefresh={refresh} />

        {auditGap && (
          <p className="text-sm text-amber-900 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2" role="alert">
            {AUDIT_INCOMPLETE_NOTE} Reference: <span className="font-mono break-all">{auditGap}</span>
          </p>
        )}

        {(record.decision_reason || record.status_reason) && (record.status === 'APPROVED' || record.status === 'REJECTED') && (
          <div className={`${CARD} p-5`}>
            <h2 className="text-sm font-semibold text-slate-900">Decision</h2>
            <p className="text-sm text-slate-700 mt-1 break-words">{record.decision_reason || record.status_reason}</p>
            {(record.decided_by_label || record.decided_at) && (
              <p className="text-xs text-slate-600 mt-1">
                {record.decided_by_label || 'Decided'} · {formatDate(record.decided_at)}
              </p>
            )}
          </div>
        )}

        {offered.note && (
          <p className="text-sm text-amber-900 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2" role="status">
            {offered.note}
          </p>
        )}
        {offered.edit && offered.editReturnsToDraft && (
          <p className="text-sm text-slate-700 bg-slate-100 rounded-lg px-3 py-2">{RETURNS_TO_DRAFT_NOTE}</p>
        )}

        {offered.decide && (
          <section aria-labelledby="decision-heading" className={`${CARD} p-5`}>
            <h2 id="decision-heading" className="text-sm font-semibold text-slate-900">Decide</h2>
            <label htmlFor="decision-reason" className="block text-sm font-medium text-slate-800 mt-3">
              Reason <span className="text-slate-600 font-normal">(required)</span>
            </label>
            <textarea
              id="decision-reason"
              rows={3}
              className="mt-1 w-full px-3 py-2 text-sm rounded-lg border border-slate-400 bg-white"
              value={reason}
              maxLength={1000}
              aria-required
              aria-invalid={reasonError ? true : undefined}
              aria-describedby={reasonError ? 'decision-reason-error' : undefined}
              onChange={(e) => {
                setReason(e.target.value);
                if (reasonError) setReasonError('');
              }}
            />
            {reasonError && <p id="decision-reason-error" className="text-xs text-red-700 mt-1">{reasonError}</p>}
            <div className="flex gap-2 mt-3">
              <button type="button" className={APPROVE} disabled={busy} onClick={() => decide('approve')}>Approve</button>
              <button type="button" className={DANGER} disabled={busy} onClick={() => decide('reject')}>Reject</button>
            </div>
          </section>
        )}

        <DiffView record={record} />

        <section aria-labelledby="registration-document" className={`${CARD} p-5`}>
          <h2 id="registration-document" className="text-sm font-semibold text-slate-900 mb-3">Governance document</h2>
          <DocumentView record={record} />
        </section>

        <History recordId={record.record_id} refreshKey={historyKey} />
      </div>
    </Page>
  );
}
