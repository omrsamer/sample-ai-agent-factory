// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, describe, expect, it, vi } from 'vitest';
import client, { ApiRequestError } from '../api/client';
import detailSrc from './RegistrationDetail.tsx?raw';
import { EMPTY_DRAFT, inputFromDraft } from './governanceSchema';
import { CONFLICT_TITLE, FORBIDDEN_TITLE, classifyFailure, registrationsApi, type AuditEvent } from './registrationsClient';
import {
  GOVERNED_REFERENCES_NOTE,
  OTHER_TENANT_NOTE,
  OWN_SUBMISSION_NOTE,
  PIPELINE_NOTE,
  REJECTED_NOTE,
  STATUS_OPTIONS,
  actsForTenant,
  authoritiesOf,
  historyActionLabel,
  historyRows,
  offeredActions,
  outcomeView,
  statusView,
} from './registrationView';

const INPUT = inputFromDraft({ ...EMPTY_DRAFT, tenantId: 'retail', agentId: 'orders-assistant' });
const SHA = 'ab'.repeat(32);

describe('registrationsApi', () => {
  afterEach(() => vi.restoreAllMocks());

  it('uses only GET, POST, PUT and DELETE on /registrations, with the documented bodies', async () => {
    const get = vi.spyOn(client, 'get').mockResolvedValue({ data: {} });
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: {} });
    const put = vi.spyOn(client, 'put').mockResolvedValue({ data: {} });
    const del = vi.spyOn(client, 'delete').mockResolvedValue({ data: {} });

    await registrationsApi.list({ status: 'PENDING_APPROVAL', tenant_id: 'retail' });
    await registrationsApi.get('Rec0000000A1');
    await registrationsApi.history('Rec0000000A1');
    await registrationsApi.create(INPUT);
    await registrationsApi.update('Rec0000000A1', INPUT);
    await registrationsApi.submit('Rec0000000A1');
    await registrationsApi.approve('Rec0000000A1', 'Evidence reviewed.', SHA);
    await registrationsApi.reject('Rec0000000A1', 'Purpose is unclear.', SHA);
    await registrationsApi.retire('Rec0000000A1', 'The product was withdrawn.');
    await registrationsApi.review('Rec0000000A1', 'Reviewed with the owner.', '2027-05-27');
    await registrationsApi.remove('Rec/1');

    expect(get.mock.calls.map((c) => c[0])).toEqual(['/registrations', '/registrations/Rec0000000A1', '/registrations/Rec0000000A1/history']);
    expect(get.mock.calls[0][1]).toEqual({ params: { status: 'PENDING_APPROVAL', tenant_id: 'retail' } });
    // Create and update send the document's fields directly, not wrapped.
    expect(post.mock.calls).toEqual([
      ['/registrations', INPUT],
      ['/registrations/Rec0000000A1/submit'],
      ['/registrations/Rec0000000A1/approve', { reason: 'Evidence reviewed.', document_sha256: SHA }],
      ['/registrations/Rec0000000A1/reject', { reason: 'Purpose is unclear.', document_sha256: SHA }],
      ['/registrations/Rec0000000A1/retire', { reason: 'The product was withdrawn.' }],
      ['/registrations/Rec0000000A1/review', { reason: 'Reviewed with the owner.', next_review_by: '2027-05-27' }],
    ]);
    expect(put.mock.calls).toEqual([['/registrations/Rec0000000A1', INPUT]]);
    expect(del.mock.calls).toEqual([['/registrations/Rec%2F1']]);
  });
});

describe('classifyFailure', () => {
  it('maps 422 validation items to form fields and keeps the rest', () => {
    const failure = classifyFailure(
      new ApiRequestError('x', 422, [
        { loc: ['body', 'agent_id'], msg: 'does not match the pattern' },
        { loc: ['body', 'golden_path', 'version'], msg: 'is required' },
        { loc: ['body', 'unknown_field'], msg: 'Extra inputs are not permitted' },
      ]),
      'fallback',
    );
    expect(failure.kind).toBe('validation');
    expect(failure.fieldErrors).toEqual({ agentId: 'does not match the pattern', goldenPathVersion: 'is required' });
    expect(failure.otherErrors).toEqual(['Extra inputs are not permitted']);
  });

  it('ties a plain 422 message to its field when it names one, and shows it above the form otherwise', () => {
    const named = 'document.riskClass must be one of minimal, limited, high, unacceptable';
    expect(classifyFailure(new ApiRequestError(named, 422, named), 'fallback').fieldErrors).toEqual({ riskClass: named });
    const plain = classifyFailure(new ApiRequestError('A reason is required.', 422, 'A reason is required.'), 'fallback');
    expect(plain.fieldErrors).toEqual({});
    expect(plain.otherErrors).toEqual(['A reason is required.']);
  });

  it('words a 403 as missing authority and keeps the server reason, hint and reference', () => {
    const body = { detail: 'the submitter cannot approve its own record (REG-11-N)', action: 'approve', request_id: 'req-123', hint: 'Ask another approver.' };
    const failure = classifyFailure(new ApiRequestError(body.detail, 403, body.detail, body), 'fallback');
    expect(failure).toMatchObject({ kind: 'forbidden', title: FORBIDDEN_TITLE, message: body.detail, hint: 'Ask another approver.', requestId: 'req-123' });
    expect(FORBIDDEN_TITLE).toBe('You do not hold the authority for this action');
  });

  it('words a 409 as a state conflict', () => {
    expect(classifyFailure(new ApiRequestError('The record changed since it was read; review it again', 409), 'fallback')).toMatchObject({
      kind: 'conflict',
      title: CONFLICT_TITLE,
      message: 'The record changed since it was read; review it again',
    });
  });

  it('shows a request that failed part-way with the server’s account of it', () => {
    const body = { detail: 'The deny statement could not be written (AccessDeniedException). Nothing was changed.', request_id: 'req-9' };
    expect(classifyFailure(new ApiRequestError(body.detail, 502, body.detail, body), 'fallback')).toMatchObject({
      kind: 'other',
      title: 'The action failed part-way',
      message: body.detail,
      requestId: 'req-9',
    });
  });

  it('words a conflict without assuming it is about a record', () => {
    expect(CONFLICT_TITLE).toBe('This cannot be done in the current state');
  });

  it('says nothing was changed when the audit trail is unavailable', () => {
    expect(classifyFailure(new ApiRequestError('The audit trail could not be written, so nothing was done', 503), 'fallback')).toMatchObject({
      kind: 'unavailable',
      title: 'Nothing was changed',
    });
  });

  it('handles a missing record, other statuses and non-API errors without throwing', () => {
    expect(classifyFailure(new ApiRequestError('gone', 404), 'fallback').kind).toBe('not_found');
    expect(classifyFailure(new ApiRequestError('boom', 500), 'Could not save')).toMatchObject({ kind: 'other', title: 'Could not save', message: 'boom' });
    expect(classifyFailure(new Error('network'), 'Could not save')).toMatchObject({ kind: 'other', message: 'network' });
    expect(classifyFailure(undefined, 'Could not save')).toMatchObject({ kind: 'other', message: '', hint: null, requestId: null });
  });
});

describe('authoritiesOf', () => {
  it('grants only what /users/me states with a boolean true', () => {
    expect(authoritiesOf({ can_register: true, can_approve: false, registration_tenants: ['retail'] })).toEqual({ registrar: true, approver: false, tenants: ['retail'] });
    expect(authoritiesOf({ can_register: true, can_approve: true, registration_tenants: ['*'] })).toEqual({ registrar: true, approver: true, tenants: null });
  });

  it('grants nothing for a missing or malformed answer', () => {
    for (const user of [null, undefined, {}, { can_register: 'true', can_approve: 1 }, { can_register: null }]) {
      expect(authoritiesOf(user)).toMatchObject({ registrar: false, approver: false });
    }
  });

  it('treats an unknown tenant list as unrestricted for display, leaving enforcement to the server', () => {
    expect(authoritiesOf({ can_register: true, registration_tenants: null }).tenants).toBeNull();
    expect(actsForTenant(authoritiesOf({ can_register: true, registration_tenants: null }), 'retail')).toBe(true);
  });
});

describe('actsForTenant', () => {
  it('requires the tenant to be in a restricted list', () => {
    const who = { registrar: true, approver: false, tenants: ['retail'] };
    expect(actsForTenant(who, 'retail')).toBe(true);
    expect(actsForTenant(who, 'finance')).toBe(false);
    expect(actsForTenant(who, null)).toBe(false);
  });
});

describe('offeredActions', () => {
  const registrar = { registrar: true, approver: false, tenants: null };
  const approver = { registrar: false, approver: true, tenants: null };
  const both = { registrar: true, approver: true, tenants: null };
  const none = { registrar: false, approver: false, tenants: null };
  const STATUSES = ['DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'DEPRECATED', 'CREATING', 'UPDATING'];

  it('offers a registrar edit, submit and delete on a draft', () => {
    expect(offeredActions({ status: 'DRAFT' }, registrar)).toMatchObject({ edit: true, submit: true, remove: true, decide: false, editLocksGovernedReferences: false, editReturnsToDraft: false });
  });

  it('offers nothing to someone with no authority', () => {
    for (const status of STATUSES) {
      expect(offeredActions({ status }, none)).toMatchObject({ edit: false, submit: false, remove: false, decide: false, note: null });
    }
  });

  it('offers an approver a decision on a pending record they did not submit', () => {
    expect(offeredActions({ status: 'PENDING_APPROVAL', submitted_by_me: false }, approver).decide).toBe(true);
    expect(offeredActions({ status: 'PENDING_APPROVAL' }, approver).decide).toBe(true);
  });

  it('never offers a decision on the caller’s own submission, and says why', () => {
    const own = offeredActions({ status: 'PENDING_APPROVAL', submitted_by_me: true }, both);
    expect(own.decide).toBe(false);
    expect(own.note).toBe(OWN_SUBMISSION_NOTE);
  });

  it('offers a decision only while pending, and submit only on a draft', () => {
    for (const status of STATUSES.filter((s) => s !== 'PENDING_APPROVAL')) {
      expect(offeredActions({ status }, both).decide).toBe(false);
    }
    for (const status of STATUSES.filter((s) => s !== 'DRAFT')) {
      expect(offeredActions({ status }, both).submit).toBe(false);
    }
  });

  it('never offers delete on an approved record', () => {
    expect(offeredActions({ status: 'APPROVED' }, both).remove).toBe(false);
    for (const status of ['DRAFT', 'PENDING_APPROVAL', 'REJECTED']) {
      expect(offeredActions({ status }, registrar).remove).toBe(true);
    }
  });

  it('locks the governed references only on an approved record, and warns that any edit of a non-draft returns it to Draft', () => {
    expect(offeredActions({ status: 'APPROVED' }, registrar)).toMatchObject({ edit: true, editLocksGovernedReferences: true, editReturnsToDraft: true });
    expect(offeredActions({ status: 'REJECTED' }, registrar)).toMatchObject({ edit: true, editLocksGovernedReferences: false, editReturnsToDraft: true, note: REJECTED_NOTE });
    expect(offeredActions({ status: 'PENDING_APPROVAL' }, registrar)).toMatchObject({ edit: true, editReturnsToDraft: true });
  });

  it('offers nothing while the registry is still working on the record', () => {
    for (const status of ['CREATING', 'UPDATING']) {
      expect(offeredActions({ status }, both)).toMatchObject({ edit: false, submit: false, remove: false, decide: false });
    }
  });

  it('offers no edit, submit or decision on a retired record; a registrar can still delete it', () => {
    expect(offeredActions({ status: 'DEPRECATED' }, both)).toMatchObject({ edit: false, submit: false, decide: false, remove: true });
    expect(offeredActions({ status: 'DEPRECATED' }, approver)).toMatchObject({ edit: false, submit: false, decide: false, remove: false });
    expect(offeredActions({ status: 'DEPRECATED', submitted_by_me: false }, approver).decide).toBe(false);
  });

  it('offers nothing on a record of a tenant the caller does not act for, and says why', () => {
    const scoped = { registrar: true, approver: true, tenants: ['retail'] };
    expect(offeredActions({ status: 'DRAFT', tenant_id: 'finance' }, scoped)).toMatchObject({ edit: false, submit: false, remove: false, decide: false, note: OTHER_TENANT_NOTE });
    expect(offeredActions({ status: 'DRAFT', tenant_id: 'retail' }, scoped).edit).toBe(true);
  });
});

describe('historyRows', () => {
  const event = (over: Partial<AuditEvent>): AuditEvent => ({
    event_id: 'e1',
    request_id: 'r1',
    at: '2026-03-01T10:00:00.000000Z',
    phase: 'result',
    action: 'submit',
    outcome: 'allowed',
    reason: 'registrar holds the tenant',
    actor_label: 'Example Registrar',
    actor_role: 'developer',
    status_before: 'DRAFT',
    status_after: 'PENDING_APPROVAL',
    ...over,
  });

  it('shows one row per action: the result, not the intent that preceded it', () => {
    const rows = historyRows([event({ event_id: 'e2' }), event({ event_id: 'e1', phase: 'intent' })]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ key: 'e2', outcome: 'allowed', actor: 'Example Registrar', role: 'developer', statusChange: 'Draft → Pending approval' });
  });

  it('keeps a denied attempt, with its reason', () => {
    const rows = historyRows([event({ action: 'approve', outcome: 'denied', reason: 'the submitter cannot approve its own record (REG-11-N)', status_after: 'PENDING_APPROVAL', status_before: 'PENDING_APPROVAL' })]);
    expect(rows[0]).toMatchObject({ outcome: 'denied', reason: 'the submitter cannot approve its own record (REG-11-N)', statusChange: '' });
  });

  it('keeps an intent whose result was never recorded, and marks it', () => {
    const rows = historyRows([event({ phase: 'intent', request_id: 'orphan' })]);
    expect(rows).toHaveLength(1);
    expect(rows[0].outcome).toBe('incomplete');
    expect(outcomeView('incomplete').label).toBe('No result recorded');
  });

  it('answers an empty list for no events', () => {
    expect(historyRows(null)).toEqual([]);
    expect(historyRows([])).toEqual([]);
  });
});

describe('wording', () => {
  it('says that a registration deploys nothing', () => {
    expect(PIPELINE_NOTE).toMatch(/deploys nothing/);
    expect(PIPELINE_NOTE).toMatch(/only through the Workload pipeline/);
    expect(GOVERNED_REFERENCES_NOTE).toMatch(/needs a new registration/);
  });

  it('labels statuses, history actions and outcomes, showing unknown values as recorded', () => {
    expect(statusView('PENDING_APPROVAL').label).toBe('Pending approval');
    expect(statusView('WITHDRAWN').label).toBe('WITHDRAWN');
    expect(statusView(null).label).toBe('Unknown');
    expect(STATUS_OPTIONS.map((o) => o.value)).toEqual(['DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'DEPRECATED']);
    // The registry says DEPRECATED; the portal says retired.
    expect(statusView('DEPRECATED').label).toBe('Retired');
    expect(STATUS_OPTIONS.find((o) => o.value === 'DEPRECATED')?.label).toBe('Retired');
    expect(historyActionLabel('retire')).toBe('Retire');
    expect(historyActionLabel('review')).toBe('Confirm review');
    expect(historyActionLabel('submit')).toBe('Submit for approval');
    expect(historyActionLabel('escalate')).toBe('escalate');
    expect(outcomeView('denied').label).toBe('Denied');
    expect(outcomeView('failed').label).toBe('Failed');
    expect(outcomeView('unchanged').label).toBe('No change');
    expect(outcomeView('').label).toBe('Unknown');
  });
});

describe('the record page', () => {
  it('renders Approve and Reject only inside the offered-decision branch', () => {
    const start = detailSrc.indexOf('{offered.decide && (');
    expect(start).toBeGreaterThan(0);
    expect(detailSrc.indexOf("decide('approve')")).toBeGreaterThan(start);
    expect(detailSrc.indexOf("decide('reject')")).toBeGreaterThan(start);
    expect(detailSrc.match(/decide\('approve'\)/g)).toHaveLength(1);
  });

  it('sends the digest of the document the approver was shown with the decision', () => {
    expect(detailSrc).toMatch(/registrationsApi\.approve\(id, trimmed, record\?\.document_sha256/);
    expect(detailSrc).toMatch(/registrationsApi\.reject\(id, trimmed, record\?\.document_sha256/);
  });

  it('uses no blocking browser dialog for the delete confirmation', () => {
    expect(detailSrc).not.toMatch(/window\.confirm|[^.]confirm\(/);
  });
});
