// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { AuditEvent, RegistrationDetail, RegistrationStatus } from './registrationsClient';

/** Pure view rules for registrations: labels, and which actions a caller is offered. */

export interface Authorities {
  registrar: boolean;
  approver: boolean;
  /** Tenants the caller acts for. `null` means every tenant, or not known to the read API. */
  tenants: string[] | null;
}

/** Reads the caller's authorities from `/users/me`. Anything absent or malformed grants nothing. */
export function authoritiesOf(
  user: { can_register?: unknown; can_approve?: unknown; registration_tenants?: unknown } | null | undefined,
): Authorities {
  const raw = user?.registration_tenants;
  const list = Array.isArray(raw) ? raw.filter((t): t is string => typeof t === 'string') : null;
  return {
    registrar: user?.can_register === true,
    approver: user?.can_approve === true,
    tenants: list === null || list.includes('*') ? null : list,
  };
}

/** True when the caller acts for the tenant, or the tenant list is not restricted or not known. */
export function actsForTenant(who: Authorities, tenantId: string | null | undefined): boolean {
  if (who.tenants === null) return true;
  return !!tenantId && who.tenants.includes(tenantId);
}

const STATUS_VIEW: Record<RegistrationStatus, { label: string; cls: string }> = {
  DRAFT: { label: 'Draft', cls: 'bg-slate-100 text-slate-700' },
  PENDING_APPROVAL: { label: 'Pending approval', cls: 'bg-amber-50 text-amber-800' },
  APPROVED: { label: 'Approved', cls: 'bg-emerald-50 text-emerald-800' },
  REJECTED: { label: 'Rejected', cls: 'bg-red-50 text-red-800' },
  // The registry calls it DEPRECATED; the portal calls such a registration retired.
  DEPRECATED: { label: 'Retired', cls: 'bg-slate-200 text-slate-800' },
  CREATING: { label: 'Creating', cls: 'bg-slate-100 text-slate-700' },
  UPDATING: { label: 'Updating', cls: 'bg-slate-100 text-slate-700' },
  CREATE_FAILED: { label: 'Create failed', cls: 'bg-red-50 text-red-800' },
  UPDATE_FAILED: { label: 'Update failed', cls: 'bg-red-50 text-red-800' },
};

/** The statuses the list can be filtered by. */
export const STATUS_OPTIONS: { value: RegistrationStatus; label: string }[] = (
  ['DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'DEPRECATED'] as RegistrationStatus[]
).map((value) => ({ value, label: STATUS_VIEW[value].label }));

export function statusView(status: string | null | undefined): { label: string; cls: string } {
  const key = status ?? '';
  return Object.prototype.hasOwnProperty.call(STATUS_VIEW, key)
    ? STATUS_VIEW[key as RegistrationStatus]
    : { label: key || 'Unknown', cls: 'bg-slate-100 text-slate-700' };
}

export interface OfferedActions {
  edit: boolean;
  /** Editing must leave the governed references as they are (an approved record). */
  editLocksGovernedReferences: boolean;
  /** Saving an edit sends the record back to Draft, to be submitted and approved again. */
  editReturnsToDraft: boolean;
  submit: boolean;
  remove: boolean;
  decide: boolean;
  /** Why a control that the caller's authority would allow is not offered on this record. */
  note: string | null;
}

export const OWN_SUBMISSION_NOTE =
  'You submitted this record, so you cannot approve or reject it. Another approver must decide.';
export const OTHER_TENANT_NOTE = 'This record belongs to a tenant you do not act for, so you cannot change or decide it.';
export const REJECTED_NOTE =
  'A rejected record cannot be submitted again as it is. Edit it, which returns it to Draft, then submit it.';
export const RETURNS_TO_DRAFT_NOTE =
  'Saving a change returns this record to Draft. It must then be submitted and approved again.';

const EDITABLE = new Set(['DRAFT', 'PENDING_APPROVAL', 'REJECTED', 'APPROVED']);
// A retired record is final: it can only be deleted, like any record that is not approved.
const RETIRED = 'DEPRECATED';

/**
 * Which controls to offer. This only decides what is shown: the server enforces every rule
 * again, and its refusal is displayed if a request is made anyway.
 */
export function offeredActions(
  record: Pick<RegistrationDetail, 'status' | 'submitted_by_me' | 'tenant_id'>,
  who: Authorities,
): OfferedActions {
  const { status } = record;
  const none: OfferedActions = {
    edit: false,
    editLocksGovernedReferences: status === 'APPROVED',
    editReturnsToDraft: status !== 'DRAFT',
    submit: false,
    remove: false,
    decide: false,
    note: null,
  };
  if (!who.registrar && !who.approver) return none;
  if (!actsForTenant(who, record.tenant_id)) return { ...none, note: OTHER_TENANT_NOTE };

  const pending = status === 'PENDING_APPROVAL';
  const ownSubmission = record.submitted_by_me === true;
  let note: string | null = null;
  if (who.approver && pending && ownSubmission) note = OWN_SUBMISSION_NOTE;
  else if (who.registrar && status === 'REJECTED') note = REJECTED_NOTE;
  return {
    ...none,
    edit: who.registrar && EDITABLE.has(status),
    submit: who.registrar && status === 'DRAFT',
    remove: who.registrar && ((EDITABLE.has(status) && status !== 'APPROVED') || status === RETIRED),
    decide: who.approver && pending && !ownSubmission,
    note,
  };
}

export const PIPELINE_NOTE =
  'A registration is a governance record. It deploys nothing: deployment still happens only through the Workload pipeline of the owning Workstream cell.';

export const GOVERNED_REFERENCES_NOTE =
  'On an approved record the runtime, tool gateway, subscribed tools, risk class and data classification cannot be edited. A change to any of them needs a new registration.';

export const AUDIT_INCOMPLETE_NOTE =
  'The action was completed, but its result could not be written to the audit trail. Tell the platform team and quote the reference.';

const ACTION_LABEL: Record<string, string> = {
  create: 'Create draft',
  update: 'Edit',
  submit: 'Submit for approval',
  approve: 'Approve',
  reject: 'Reject',
  delete: 'Delete',
  retire: 'Retire',
  review: 'Confirm review',
};

export function historyActionLabel(action: string): string {
  return Object.prototype.hasOwnProperty.call(ACTION_LABEL, action) ? ACTION_LABEL[action] : action;
}

export function outcomeView(outcome: string): { label: string; cls: string } {
  if (outcome === 'allowed') return { label: 'Allowed', cls: 'bg-emerald-50 text-emerald-800' };
  if (outcome === 'denied') return { label: 'Denied', cls: 'bg-red-50 text-red-800' };
  if (outcome === 'failed') return { label: 'Failed', cls: 'bg-red-50 text-red-800' };
  if (outcome === 'unchanged') return { label: 'No change', cls: 'bg-slate-100 text-slate-700' };
  // A background sweep that found its agent released, and so stopped nothing.
  if (outcome === 'skipped') return { label: 'Skipped', cls: 'bg-slate-100 text-slate-700' };
  if (outcome === 'incomplete') return { label: 'No result recorded', cls: 'bg-amber-50 text-amber-800' };
  return { label: outcome || 'Unknown', cls: 'bg-slate-100 text-slate-700' };
}

/** Shown under a history whose older entries the API did not list. */
export const HISTORY_TRUNCATED_NOTE = 'Only the newest entries are listed. Older entries exist and are not shown here.';

export interface HistoryRow {
  key: string;
  at: string;
  actor: string;
  role: string;
  action: string;
  /** `allowed`, `denied`, `failed`, or `incomplete` for an intent with no result. */
  outcome: string;
  reason: string;
  statusChange: string;
  /** The date a review, or an approval that recorded one, set for the next review. */
  nextReviewBy: string;
}

/**
 * One row per action. An allowed action is written as an intent and a result that share a
 * request id: the result is the row. An intent whose result never arrived is kept and marked,
 * because an action that may have happened without a recorded result is worth seeing.
 *
 * A result answers the intent of the same request and the same action. A background sweep
 * carries the request id of the contain that scheduled it, and is a row of its own: it never
 * stands in for that contain's result.
 */
export function historyRows(events: readonly AuditEvent[] | null | undefined): HistoryRow[] {
  const list = events ?? [];
  const answered = (e: AuditEvent) => `${e.request_id}\u0000${e.action}`;
  const withResult = new Set(list.filter((e) => e.phase === 'result').map(answered));
  return list
    .filter((e) => e.phase === 'result' || !withResult.has(answered(e)))
    .map((e) => ({
      key: e.event_id,
      at: e.at,
      actor: e.actor_label,
      role: e.actor_role ?? '',
      action: e.action,
      outcome: e.phase === 'result' ? e.outcome : 'incomplete',
      reason: e.reason ?? '',
      statusChange:
        e.status_before && e.status_after && e.status_before !== e.status_after
          ? `${statusView(e.status_before).label} → ${statusView(e.status_after).label}`
          : '',
      nextReviewBy: e.next_review_by ?? '',
    }));
}
