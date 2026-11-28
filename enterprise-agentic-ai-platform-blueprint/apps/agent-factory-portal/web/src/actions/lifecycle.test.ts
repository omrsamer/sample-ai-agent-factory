// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import panelSrc from './AgentRegistrationPanel.tsx?raw';
import actionsSrc from './LifecycleActions.tsx?raw';
import detailSrc from './RegistrationDetail.tsx?raw';
import followUpSrc from './RetiredFollowUp.tsx?raw';
import {
  REVIEW_MAX_DAYS,
  REVIEW_SUGGESTED_DAYS,
  RETIRED_NOTE,
  RETIRE_KEEPS_RUNTIME,
  RETIRE_PERMANENT,
  addDays,
  agentAfterRetire,
  agentAfterReview,
  agentFromRegistration,
  offeredLifecycle,
  retireMessage,
  reviewDateBounds,
  reviewMessage,
  reviewServerErrors,
  reviewState,
  utcDate,
  validateReview,
  OWN_SUBMISSION_REVIEW_NOTE,
  REVIEWED_JUST_NOW_NOTE,
} from './lifecycleView';
import { historyRows } from './registrationView';
import type { AuditEvent, RegistrationDetail } from './registrationsClient';

// A fixed instant: 2026-11-27, late evening in UTC.
const NOW = new Date('2026-11-27T22:30:00Z');

describe('offeredLifecycle', () => {
  const approver = { registrar: false, approver: true, tenants: null };
  const registrar = { registrar: true, approver: false, tenants: null };
  const scoped = { registrar: false, approver: true, tenants: ['retail'] };

  it('offers retire to an approver on every registration that is not retired', () => {
    for (const status of ['DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED']) {
      expect(offeredLifecycle({ status }, approver).retire).toBe(true);
    }
    expect(offeredLifecycle({ status: 'DEPRECATED' }, approver)).toEqual({ retire: false, review: false, reviewBlocked: false });
  });

  it('offers a review only on an approved registration', () => {
    expect(offeredLifecycle({ status: 'APPROVED' }, approver).review).toBe(true);
    for (const status of ['DRAFT', 'PENDING_APPROVAL', 'REJECTED', 'DEPRECATED']) {
      expect(offeredLifecycle({ status }, approver).review).toBe(false);
    }
  });

  it('offers neither without the approver authority, or for a tenant the caller does not hold', () => {
    const nothing = { retire: false, review: false, reviewBlocked: false };
    expect(offeredLifecycle({ status: 'APPROVED' }, registrar)).toEqual(nothing);
    expect(offeredLifecycle({ status: 'APPROVED', tenant_id: 'finance' }, scoped)).toEqual(nothing);
    expect(offeredLifecycle({ status: 'APPROVED', tenant_id: 'retail' }, scoped)).toEqual({ retire: true, review: true, reviewBlocked: false });
  });

  it('shows the review as unavailable to the person who submitted the registration, and still lets them retire it', () => {
    // A review is a second pair of eyes, as an approval is. Retiring has no such rule.
    expect(offeredLifecycle({ status: 'APPROVED', submitted_by_me: true }, approver)).toEqual({ retire: true, review: false, reviewBlocked: true });
    expect(offeredLifecycle({ status: 'APPROVED', submitted_by_me: false }, approver)).toEqual({ retire: true, review: true, reviewBlocked: false });
    // Only an approved registration has a review to block, and only for a caller who could otherwise confirm it.
    expect(offeredLifecycle({ status: 'PENDING_APPROVAL', submitted_by_me: true }, approver).reviewBlocked).toBe(false);
    expect(offeredLifecycle({ status: 'APPROVED', submitted_by_me: true }, registrar).reviewBlocked).toBe(false);
    expect(OWN_SUBMISSION_REVIEW_NOTE).toBe('You submitted this registration, so you cannot confirm its review. Another approver must.');
    expect(REVIEWED_JUST_NOW_NOTE).toBe('Its review was confirmed just now. Another one can be recorded after 24 hours.');
  });
});

describe('review dates', () => {
  it('counts days in UTC, as the server does', () => {
    expect(utcDate(NOW)).toBe('2026-11-27');
    // Just after midnight UTC it is already the next day, whatever the local clock says.
    expect(utcDate(new Date('2026-11-28T00:00:01Z'))).toBe('2026-11-28');
    expect(addDays('2026-11-27', 1)).toBe('2026-11-28');
    expect(addDays('2026-12-31', 1)).toBe('2027-01-01');
    expect(addDays('2028-02-28', 1)).toBe('2028-02-29');
  });

  it('allows tomorrow through today plus 366 days, and proposes today plus 180', () => {
    expect(reviewDateBounds(NOW)).toEqual({ today: '2026-11-27', min: '2026-11-28', max: '2027-11-28', suggested: '2027-05-26' });
    expect(REVIEW_MAX_DAYS).toBe(366);
    expect(REVIEW_SUGGESTED_DAYS).toBe(180);
  });

  it('accepts a reason and a date inside the bounds', () => {
    expect(validateReview({ reason: 'Reviewed with the owner.', nextReviewBy: '2027-05-26' }, NOW)).toEqual({});
    expect(validateReview({ reason: 'x', nextReviewBy: '2026-11-28' }, NOW)).toEqual({});
    expect(validateReview({ reason: 'x', nextReviewBy: '2027-11-28' }, NOW)).toEqual({});
  });

  it('refuses today, the past and anything more than 366 days ahead, and says the limit', () => {
    expect(validateReview({ reason: 'x', nextReviewBy: '2026-11-27' }, NOW).nextReviewBy).toBe('Choose a date after today, 2026-11-27 in UTC.');
    expect(validateReview({ reason: 'x', nextReviewBy: '2025-01-01' }, NOW).nextReviewBy).toMatch(/after today/);
    expect(validateReview({ reason: 'x', nextReviewBy: '2027-11-29' }, NOW).nextReviewBy).toBe(
      'Choose 2027-11-28 or an earlier date: the next review can be at most 366 days ahead.',
    );
  });

  it('refuses a missing or impossible date and a missing or over-long reason', () => {
    expect(validateReview({ reason: 'x', nextReviewBy: '' }, NOW).nextReviewBy).toBe('Choose the next review date.');
    expect(validateReview({ reason: 'x', nextReviewBy: '2027-02-30' }, NOW).nextReviewBy).toMatch(/year-month-day/);
    expect(validateReview({ reason: '   ', nextReviewBy: '2027-05-26' }, NOW).reason).toBe('A reason is required.');
    expect(validateReview({ reason: 'r'.repeat(1001), nextReviewBy: '2027-05-26' }, NOW).reason).toBe('The reason must be 1000 characters or fewer.');
    expect(validateReview({ reason: 'r'.repeat(1000), nextReviewBy: '2027-05-26' }, NOW)).toEqual({});
  });

  it('ties the server’s validation errors to the two fields', () => {
    const detail = [
      { loc: ['body', 'next_review_by'], msg: 'next_review_by must be after today, 2026-11-27 in UTC (REV-04-N)', type: 'review_date' },
      { loc: ['body', 'reason'], msg: 'reason must not be empty', type: 'string_too_short' },
      { loc: ['body'], msg: 'an unknown field was sent', type: 'extra_forbidden' },
    ];
    expect(reviewServerErrors(detail)).toEqual({
      nextReviewBy: 'next_review_by must be after today, 2026-11-27 in UTC (REV-04-N)',
      reason: 'reason must not be empty',
      other: ['an unknown field was sent'],
    });
    for (const bad of [null, undefined, 'text', {}, [null, 7, { msg: 3 }]]) expect(reviewServerErrors(bad)).toEqual({ other: [] });
  });
});

describe('reviewState', () => {
  const record = (over: object) => ({ status: 'APPROVED', document: { review_by: '2026-06-30' } as never, ...over });

  it('uses the effective review date, which a later attestation moves', () => {
    expect(reviewState(record({ effective_review_by: '2027-05-26', last_reviewed_at: '2026-11-27T10:00:00Z', last_reviewed_by: 'Example Approver' }), NOW)).toEqual({
      due: '2027-05-26',
      overdue: false,
      lastReviewedAt: '2026-11-27T10:00:00Z',
      lastReviewedBy: 'Example Approver',
    });
  });

  it('falls back to the document’s own date when no attestation exists', () => {
    expect(reviewState(record({}), NOW)).toMatchObject({ due: '2026-06-30', overdue: true, lastReviewedAt: null });
  });

  it('is overdue only for an approved registration whose date has passed', () => {
    expect(reviewState(record({ effective_review_by: '2026-11-26' }), NOW).overdue).toBe(true);
    // Due today is not overdue yet.
    expect(reviewState(record({ effective_review_by: '2026-11-27' }), NOW).overdue).toBe(false);
    // A retired registration can no longer be reviewed, so it is never overdue.
    expect(reviewState(record({ status: 'DEPRECATED', effective_review_by: '2020-01-01' }), NOW).overdue).toBe(false);
    expect(reviewState({ status: 'APPROVED', document: {} as never }, NOW)).toMatchObject({ due: '', overdue: false });
  });
});

describe('wording', () => {
  it('says both things a retire confirmation must say', () => {
    expect(RETIRE_PERMANENT).toBe(
      'Retiring is permanent: the registration cannot be approved, changed or submitted again. To bring the agent back, register it again.',
    );
    expect(RETIRE_KEEPS_RUNTIME).toMatch(/keeps running until its pipeline removes it/);
    expect(RETIRED_NOTE).toMatch(/can no longer be approved, rejected, edited, submitted or reviewed/);
  });

  it('shows the server’s sentence after a retire, and says when nothing was changed', () => {
    const sentence = 'The registration is retired. Retirement is permanent: the record can no longer be approved, rejected, updated or submitted.';
    expect(retireMessage({ outcome: 'allowed', reason: sentence })).toBe(sentence);
    expect(retireMessage({ outcome: 'unchanged', reason: 'The registration was already retired; nothing was changed.' })).toBe(
      'The registration was already retired. Nothing was changed.',
    );
    expect(retireMessage({ outcome: 'allowed', reason: ' ' })).toMatch(/Retirement is permanent/);
    expect(reviewMessage('2027-05-26')).toBe('Review confirmed. The next review is due by 2027-05-26.');
  });
});

describe('what the agent page shows right after an action', () => {
  it('moves the review date and clears "review overdue" after a review, without naming a reviewer of its own', () => {
    // Who the review is recorded under is the API's to say: it is not the caller's display name.
    expect(agentAfterReview('2027-05-26', '2026-11-27T22:30:00.000Z')).toEqual({
      review_by: '2027-05-26',
      last_reviewed_at: '2026-11-27T22:30:00.000Z',
      last_reviewed_by: null,
      // Only the flag the action settled: every other flag stays as the API sends it.
      flags: { review_overdue: false },
    });
  });

  it('takes the review as recorded from the registration once it has been read again', () => {
    const now = new Date('2026-11-27T22:31:00Z');
    const reviewed = {
      status: 'APPROVED',
      effective_review_by: '2027-05-26',
      last_reviewed_at: '2026-11-27T22:30:00.123456Z',
      last_reviewed_by: 'approver@example.com',
      document: { review_by: '2026-01-31' } as RegistrationDetail['document'],
    };
    expect(agentFromRegistration(reviewed, now)).toEqual({
      review_by: '2027-05-26',
      last_reviewed_at: '2026-11-27T22:30:00.123456Z',
      last_reviewed_by: 'approver@example.com',
      flags: { review_overdue: false },
    });
    // No attestation: the document's own date, which can be overdue, and nobody to name.
    expect(agentFromRegistration({ status: 'APPROVED', document: reviewed.document }, now)).toEqual({
      review_by: '2026-01-31',
      last_reviewed_at: null,
      last_reviewed_by: null,
      flags: { review_overdue: true },
    });
    // No date at all: nothing is overdue, and the page falls back to the document's own date.
    expect(agentFromRegistration({ status: 'APPROVED', document: {} as RegistrationDetail['document'] }, now)).toMatchObject({
      review_by: null,
      flags: { review_overdue: false },
    });
  });

  it('reads a retired registration as retired, and says nothing for one that is neither approved nor retired', () => {
    const now = new Date('2026-11-27T22:31:00Z');
    const document = { review_by: '2026-01-31' } as RegistrationDetail['document'];
    expect(agentFromRegistration({ status: 'DEPRECATED', document }, now)).toEqual(agentAfterRetire());
    for (const status of ['DRAFT', 'PENDING_APPROVAL', 'REJECTED', 'UPDATING', 'SOMETHING_NEW']) {
      expect(agentFromRegistration({ status, document }, now)).toBeNull();
    }
  });

  it('shows a retired registration as retired and never overdue, and asserts nothing else about its flags', () => {
    // With nothing deployed the API closes its obligations and its other flags do not apply.
    expect(agentAfterRetire()).toEqual({
      lifecycle_state: 'deprecated',
      registry_status: 'DEPRECATED',
      flags: { review_overdue: false },
    });
  });
});

describe('history', () => {
  const event = (over: Partial<AuditEvent>): AuditEvent => ({
    event_id: 'e',
    request_id: 'r',
    at: '2026-11-27T10:00:00Z',
    phase: 'result',
    action: 'review',
    outcome: 'allowed',
    reason: 'Reviewed with the owner.',
    actor_label: 'Example Approver',
    ...over,
  });

  it('carries the next review date of a review, and of an approval that recorded one', () => {
    const rows = historyRows([
      event({ event_id: 'e2', request_id: 'r2', next_review_by: '2027-05-26' }),
      event({ event_id: 'e1', request_id: 'r1', action: 'approve', next_review_by: '2026-12-31', status_before: 'PENDING_APPROVAL', status_after: 'APPROVED' }),
      event({ event_id: 'e0', request_id: 'r0', action: 'retire', status_before: 'APPROVED', status_after: 'DEPRECATED' }),
    ]);
    expect(rows.map((r) => [r.action, r.nextReviewBy, r.statusChange])).toEqual([
      ['review', '2027-05-26', ''],
      ['approve', '2026-12-31', 'Pending approval → Approved'],
      ['retire', '', 'Approved → Retired'],
    ]);
  });
});

describe('the lifecycle controls', () => {
  it('enable Retire only once a reason is entered, and send nothing without one', () => {
    expect(actionsSrc).toContain('disabled={busy || !hasReason} aria-describedby={id(\'retire-reason-hint\')} onClick={() => void retire()}');
    expect(actionsSrc).toContain('if (!trimmed) return;');
  });

  it('state both consequences before the retire button, in the destructive style', () => {
    const confirm = actionsSrc.slice(actionsSrc.indexOf('<li>{RETIRE_PERMANENT}</li>'));
    expect(confirm.indexOf('<li>{RETIRE_KEEPS_RUNTIME}</li>')).toBeGreaterThan(0);
    expect(confirm.indexOf('<li>{RETIRE_KEEPS_RUNTIME}</li>')).toBeLessThan(confirm.indexOf('onClick={() => void retire()}'));
    expect(confirm.slice(0, confirm.indexOf('onClick={() => void retire()}'))).toContain('className={DANGER}');
  });

  it('limit the date input to what the server accepts and check the form before sending', () => {
    expect(actionsSrc).toContain('min={bounds.min}');
    expect(actionsSrc).toContain('max={bounds.max}');
    expect(actionsSrc).toContain('const [date, setDate] = useState(bounds.suggested);');
    const confirm = actionsSrc.slice(actionsSrc.indexOf('const confirmReview = async'), actionsSrc.indexOf('const retire = async'));
    expect(confirm.indexOf('validateReview(')).toBeLessThan(confirm.indexOf('registrationsApi.review('));
    expect(confirm).toContain('if (found.reason || found.nextReviewBy) return;');
  });

  it('show the review section on an approved registration only, and each action only when offered', () => {
    expect(actionsSrc).toContain("const showReview = record.status === 'APPROVED';");
    expect(actionsSrc).toContain("{offered.review && !reviewedNow && mode !== 'review' && (");
    expect(actionsSrc).toContain('{offered.retire && (');
  });

  it('show the review as a disabled button with the reason, for the submitter and right after a review', () => {
    const blocked = actionsSrc.slice(actionsSrc.indexOf('{(offered.reviewBlocked || (offered.review && reviewedNow)) && ('));
    expect(blocked.slice(0, 500)).toContain("disabled aria-describedby={id('review-unavailable')}");
    expect(blocked.slice(0, 700)).toContain('{offered.reviewBlocked ? OWN_SUBMISSION_REVIEW_NOTE : REVIEWED_JUST_NOW_NOTE}');
    // A review made here is known to be a review: the next one would be refused for 24 hours.
    expect(actionsSrc).toContain("if (action === 'review') setReviewedNow(true);");
  });

  it('use no blocking browser dialog', () => {
    for (const src of [actionsSrc, panelSrc]) expect(src).not.toMatch(/window\.confirm|[^.]confirm\(/);
  });

  it('say on a retired registration why nothing can be done, on its page and on the agent page', () => {
    expect(detailSrc).toContain('{record.status === RETIRED_STATUS && (');
    expect(detailSrc).toContain('{RETIRED_NOTE}');
    expect(panelSrc).toContain('{record.status === RETIRED_STATUS && <p className="text-sm text-slate-800 mt-3">{RETIRED_NOTE}</p>}');
  });

  it('hand the agent page what the action made true, as the registration records it', () => {
    // The registration is read again after the action; its facts win over what the page assumed.
    expect(panelSrc).toContain('const next = await registrationsApi.get(agent.id);');
    expect(panelSrc).toContain('onChanged(agentFromRegistration(next, new Date()) ?? known);');
    // If that read fails the page still shows what it knows, and names no reviewer of its own.
    expect(panelSrc).toContain(
      "const known = done.action === 'retire' ? agentAfterRetire() : agentAfterReview(done.nextReviewBy, new Date().toISOString());",
    );
    expect(panelSrc).not.toContain('userLabel');
  });

  it('say on a retired registration when the runtime is still deployed, from the agent, with what is left to do', () => {
    expect(detailSrc).toContain('<RetiredFollowUp recordId={record.record_id} />');
    // The registration is retired whatever the agent's cached record says; only a detected runtime adds the note.
    expect(followUpSrc).toContain('const reason = retiredRuntimeReason({ ...agent, lifecycle_state: RETIRED_LIFECYCLE });');
    expect(followUpSrc).toContain('if (!reason) return null;');
    expect(followUpSrc).toContain('{RETIRED_FOLLOW_UP}');
    // It reads, and never writes.
    expect(followUpSrc).toContain('agentsApi.get(recordId)');
    expect(followUpSrc).not.toMatch(/registrationsApi|containmentApi|\.post\(|\.put\(|\.delete\(/);
  });

  it('say under the registration history when only its newest entries are listed', () => {
    expect(detailSrc).toContain('{!loading && rows.length > 0 && data?.events_truncated === true && <p className="text-xs text-slate-600 mt-2">{HISTORY_TRUNCATED_NOTE}</p>}');
  });

  it('read the registration again after a refusal on the agent page, which can mean it changed', () => {
    expect(panelSrc).toContain('onRefused={reload}');
  });
});
