// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState } from 'react';
import { ApiRequestError } from '../api/client';
import { Badge, CARD, formatDate } from '../components/shared/ui';
import ActionFailurePanel from './ActionFailurePanel';
import {
  OWN_SUBMISSION_REVIEW_NOTE,
  REASON_MAX,
  REVIEWED_JUST_NOW_NOTE,
  RETIRE_KEEPS_RUNTIME,
  RETIRE_PERMANENT,
  offeredLifecycle,
  retireMessage,
  reviewDateBounds,
  reviewMessage,
  reviewServerErrors,
  reviewState,
  validateReview,
  type ReviewErrors,
} from './lifecycleView';
import { classifyFailure, registrationsApi, type ActionFailure, type ActionResult, type RegistrationDetail } from './registrationsClient';
import { AUDIT_INCOMPLETE_NOTE, type Authorities } from './registrationView';

const PRIMARY = 'px-3.5 py-1.5 rounded-lg bg-blue-700 text-white text-sm font-medium hover:bg-blue-800 disabled:opacity-50';
const SECONDARY = 'px-3.5 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 text-sm font-medium hover:bg-slate-50 disabled:opacity-50';
const DANGER = 'px-3.5 py-1.5 rounded-lg bg-red-700 text-white text-sm font-medium hover:bg-red-800 disabled:opacity-50';
const INPUT = 'mt-1 px-3 py-2 text-sm rounded-lg border border-slate-400 bg-white';

export type LifecycleAction = 'retire' | 'review';

/** What a finished action hands to the page: what was done, the server's answer, and what was sent. */
export interface LifecycleDone {
  action: LifecycleAction;
  result: ActionResult;
  /** The date the review set. Empty for a retire. */
  nextReviewBy: string;
}

/**
 * The two things that happen to a registration after approval: attesting its periodic review
 * and retiring it. Used on the registration page and on the agent page. Each action needs a
 * reason and is recorded in the registration's history; neither deploys or removes anything.
 *
 * `idPrefix` keeps the form ids unique where the component sits next to other forms.
 */
export default function LifecycleActions({
  record,
  who,
  onDone,
  onRefused,
  idPrefix = 'lifecycle',
}: {
  record: RegistrationDetail;
  who: Authorities;
  onDone: (done: LifecycleDone) => void;
  /** Called after a refusal, which the server records: the page reads the history again. */
  onRefused?: () => void;
  idPrefix?: string;
}) {
  // Read once per mount: the clock decides what "after today" means and what is overdue.
  const [now] = useState(() => new Date());
  const bounds = reviewDateBounds(now);
  const offered = offeredLifecycle(record, who);
  const review = reviewState(record, now);
  const [mode, setMode] = useState<LifecycleAction | null>(null);
  const [reason, setReason] = useState('');
  const [date, setDate] = useState(bounds.suggested);
  const [errors, setErrors] = useState<ReviewErrors>({});
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<ActionFailure | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [auditGap, setAuditGap] = useState<string | null>(null);
  // A review can be attested once in 24 hours. After one made here the control says so instead
  // of offering a request that will be refused.
  const [reviewedNow, setReviewedNow] = useState(false);

  const id = (name: string) => `${idPrefix}-${name}`;
  const hasReason = reason.trim() !== '';

  const open = (next: LifecycleAction) => {
    setMode(next);
    setReason('');
    setDate(bounds.suggested);
    setErrors({});
    setFailure(null);
    setMessage(null);
  };

  const finish = (action: LifecycleAction, result: ActionResult, nextReviewBy: string) => {
    setMode(null);
    if (action === 'review') setReviewedNow(true);
    setMessage(action === 'retire' ? retireMessage(result) : reviewMessage(nextReviewBy));
    setAuditGap(result.audit_complete === false ? result.request_id : null);
    onDone({ action, result, nextReviewBy });
  };

  const fail = (err: unknown, fallback: string) => {
    // A validation error of the review is tied to its two fields; anything else is shown whole.
    const fields = err instanceof ApiRequestError && err.status === 422 ? reviewServerErrors(err.detail) : null;
    if (fields && (fields.reason || fields.nextReviewBy)) {
      setErrors({ reason: fields.reason, nextReviewBy: fields.nextReviewBy });
      setFailure(fields.other.length > 0 ? classifyFailure(err, fallback) : null);
    } else {
      setFailure(classifyFailure(err, fallback));
    }
    onRefused?.();
  };

  const confirmReview = async () => {
    const found = validateReview({ reason, nextReviewBy: date }, now);
    setErrors(found);
    if (found.reason || found.nextReviewBy) return;
    setBusy(true);
    setFailure(null);
    try {
      finish('review', await registrationsApi.review(record.record_id, reason.trim(), date), date);
    } catch (err) {
      fail(err, 'The review could not be recorded');
    } finally {
      setBusy(false);
    }
  };

  const retire = async () => {
    const trimmed = reason.trim();
    // The button is enabled only once a reason is entered; nothing is sent without one.
    if (!trimmed) return;
    setBusy(true);
    setFailure(null);
    try {
      finish('retire', await registrationsApi.retire(record.record_id, trimmed), '');
    } catch (err) {
      fail(err, 'The registration could not be retired');
    } finally {
      setBusy(false);
    }
  };

  const showReview = record.status === 'APPROVED';
  if (!showReview && !offered.retire && !message && !failure) return null;

  return (
    <div className="space-y-4">
      {message && (
        <p className="text-sm text-slate-900 bg-emerald-50 border border-emerald-200 rounded-lg px-3 py-2" role="status">
          {message}
        </p>
      )}
      {auditGap && (
        <p className="text-sm text-amber-900 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2" role="alert">
          {AUDIT_INCOMPLETE_NOTE} Reference: <span className="font-mono break-all">{auditGap}</span>
        </p>
      )}
      <ActionFailurePanel failure={failure} />

      {showReview && (
        <section aria-labelledby={id('review-heading')} className={`${CARD} p-5`}>
          <h2 id={id('review-heading')} className="text-sm font-semibold text-slate-900">Periodic review</h2>
          <dl className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-3 text-sm">
            <div>
              <dt className="text-xs font-medium text-slate-700">Review due</dt>
              <dd className="text-slate-900">
                {review.due || <span className="text-slate-600">No review date</span>}
                {review.overdue && <Badge cls="ml-2 bg-amber-50 text-amber-900" label="Review overdue" />}
              </dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-slate-700">Last reviewed</dt>
              <dd className="text-slate-900 break-words">
                {review.lastReviewedAt ? (
                  <>
                    {formatDate(review.lastReviewedAt)}
                    {review.lastReviewedBy ? ` by ${review.lastReviewedBy}` : ''}
                  </>
                ) : (
                  <span className="text-slate-600">Not reviewed yet</span>
                )}
              </dd>
            </div>
          </dl>
          {offered.review && !reviewedNow && mode !== 'review' && (
            <button type="button" className={`${PRIMARY} mt-3`} onClick={() => open('review')}>
              Confirm review
            </button>
          )}
          {/* Shown, visibly unavailable, with the reason: for the submitter, and right after a review. */}
          {(offered.reviewBlocked || (offered.review && reviewedNow)) && (
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button type="button" className={PRIMARY} disabled aria-describedby={id('review-unavailable')}>
                Confirm review
              </button>
              <p id={id('review-unavailable')} className="text-sm text-slate-800">
                {offered.reviewBlocked ? OWN_SUBMISSION_REVIEW_NOTE : REVIEWED_JUST_NOW_NOTE}
              </p>
            </div>
          )}
          {mode === 'review' && (
            <div className="mt-4 border-t border-slate-200 pt-4">
              <p className="text-sm text-slate-800">
                Confirming a review records that you reviewed this registration and by when it must be reviewed again. The
                registration itself is not changed.
              </p>
              <label htmlFor={id('review-date')} className="block text-sm font-medium text-slate-800 mt-3">
                Next review by <span className="text-slate-600 font-normal">(required)</span>
              </label>
              <input
                id={id('review-date')}
                type="date"
                className={INPUT}
                value={date}
                min={bounds.min}
                max={bounds.max}
                aria-required
                aria-invalid={errors.nextReviewBy ? true : undefined}
                aria-describedby={`${id('review-date-hint')}${errors.nextReviewBy ? ` ${id('review-date-error')}` : ''}`}
                onChange={(e) => {
                  setDate(e.target.value);
                  if (errors.nextReviewBy) setErrors((current) => ({ ...current, nextReviewBy: undefined }));
                }}
              />
              <p id={id('review-date-hint')} className="text-xs text-slate-600 mt-1">
                After today and no later than {bounds.max}, counted in UTC.
              </p>
              {errors.nextReviewBy && <p id={id('review-date-error')} className="text-xs text-red-700 mt-1">{errors.nextReviewBy}</p>}
              <label htmlFor={id('review-reason')} className="block text-sm font-medium text-slate-800 mt-3">
                Reason <span className="text-slate-600 font-normal">(required)</span>
              </label>
              <textarea
                id={id('review-reason')}
                rows={3}
                maxLength={REASON_MAX}
                className={`${INPUT} w-full`}
                value={reason}
                aria-required
                aria-invalid={errors.reason ? true : undefined}
                aria-describedby={errors.reason ? id('review-reason-error') : undefined}
                onChange={(e) => {
                  setReason(e.target.value);
                  if (errors.reason) setErrors((current) => ({ ...current, reason: undefined }));
                }}
              />
              {errors.reason && <p id={id('review-reason-error')} className="text-xs text-red-700 mt-1">{errors.reason}</p>}
              <div className="flex gap-2 mt-3">
                <button type="button" className={PRIMARY} disabled={busy || !hasReason} onClick={() => void confirmReview()}>
                  {busy ? 'Working…' : 'Confirm review'}
                </button>
                <button type="button" className={SECONDARY} disabled={busy} onClick={() => setMode(null)}>
                  Cancel
                </button>
              </div>
            </div>
          )}
        </section>
      )}

      {offered.retire && (
        <section aria-labelledby={id('retire-heading')} className={`${CARD} p-5`}>
          <h2 id={id('retire-heading')} className="text-sm font-semibold text-slate-900">Retire this registration</h2>
          {mode !== 'retire' ? (
            <>
              <p className="text-sm text-slate-700 mt-1">For an agent that is no longer wanted. Retiring cannot be undone.</p>
              <button type="button" className={`${DANGER} mt-3`} onClick={() => open('retire')}>
                Retire registration
              </button>
            </>
          ) : (
            <>
              <ul className="mt-2 list-disc list-inside text-sm text-slate-800 space-y-0.5">
                <li>{RETIRE_PERMANENT}</li>
                <li>{RETIRE_KEEPS_RUNTIME}</li>
              </ul>
              <label htmlFor={id('retire-reason')} className="block text-sm font-medium text-slate-800 mt-4">
                Reason <span className="text-slate-600 font-normal">(required)</span>
              </label>
              <textarea
                id={id('retire-reason')}
                rows={3}
                maxLength={REASON_MAX}
                className={`${INPUT} w-full`}
                value={reason}
                aria-required
                aria-describedby={id('retire-reason-hint')}
                onChange={(e) => setReason(e.target.value)}
              />
              <p id={id('retire-reason-hint')} className="text-xs text-slate-600 mt-1">
                The reason is recorded in the history. The button is available once a reason is entered.
              </p>
              <div className="flex gap-2 mt-3">
                <button type="button" className={DANGER} disabled={busy || !hasReason} aria-describedby={id('retire-reason-hint')} onClick={() => void retire()}>
                  {busy ? 'Working…' : 'Retire registration'}
                </button>
                <button type="button" className={SECONDARY} disabled={busy} onClick={() => setMode(null)}>
                  Cancel
                </button>
              </div>
            </>
          )}
        </section>
      )}
    </div>
  );
}
