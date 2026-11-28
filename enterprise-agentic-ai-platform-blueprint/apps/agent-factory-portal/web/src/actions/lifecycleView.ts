// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { Agent } from '../api/client';
import { isCalendarDate } from './governanceSchema';
import type { ActionResult, RegistrationDetail } from './registrationsClient';
import { actsForTenant, type Authorities } from './registrationView';

/**
 * Pure view rules for what happens to a registration after approval: retiring it and attesting
 * its periodic review. The server enforces every rule itself; these decide what is offered and
 * check a form the way the server will.
 */

/** What the retire confirmation must say, in these words. */
export const RETIRE_PERMANENT =
  'Retiring is permanent: the registration cannot be approved, changed or submitted again. To bring the agent back, register it again.';
export const RETIRE_KEEPS_RUNTIME = 'The runtime keeps running until its pipeline removes it. Retiring removes nothing that is deployed.';

/** Shown on a retired registration, so nobody looks for a control that cannot exist. */
export const RETIRED_NOTE =
  'This registration is retired, which is permanent. It can no longer be approved, rejected, edited, submitted or reviewed. To bring the agent back, register it again.';

export const RETIRED_STATUS = 'DEPRECATED';

export interface OfferedLifecycle {
  retire: boolean;
  review: boolean;
  /**
   * True for the person who submitted the registration: a review is a second pair of eyes, as
   * an approval is, so "Confirm review" is shown, visibly unavailable, with the reason.
   */
  reviewBlocked: boolean;
}

export const OWN_SUBMISSION_REVIEW_NOTE = 'You submitted this registration, so you cannot confirm its review. Another approver must.';
export const REVIEWED_JUST_NOW_NOTE = 'Its review was confirmed just now. Another one can be recorded after 24 hours.';

/**
 * Retire and review use the approver authority for the record's tenant. Retire has no
 * two-person rule and is offered on every registration that is not retired. Review is offered
 * on an approved one, to anyone but its submitter.
 */
export function offeredLifecycle(
  record: Pick<RegistrationDetail, 'status' | 'tenant_id'> & Partial<Pick<RegistrationDetail, 'submitted_by_me'>>,
  who: Authorities,
): OfferedLifecycle {
  if (!who.approver || !actsForTenant(who, record.tenant_id)) return { retire: false, review: false, reviewBlocked: false };
  const approved = record.status === 'APPROVED';
  const ownSubmission = record.submitted_by_me === true;
  return { retire: record.status !== RETIRED_STATUS, review: approved && !ownSubmission, reviewBlocked: approved && ownSubmission };
}

const DAY_MS = 86_400_000;

/** How far ahead the next review may be set, and what the form proposes. */
export const REVIEW_MAX_DAYS = 366;
export const REVIEW_SUGGESTED_DAYS = 180;
export const REASON_MAX = 1000;

/** The calendar date of an instant, in UTC, as the server counts it. */
export function utcDate(now: Date): string {
  return now.toISOString().slice(0, 10);
}

export function addDays(date: string, days: number): string {
  const [year, month, day] = date.split('-').map(Number);
  return new Date(Date.UTC(year, month - 1, day) + days * DAY_MS).toISOString().slice(0, 10);
}

export interface ReviewDateBounds {
  today: string;
  /** The first date the server accepts: tomorrow. */
  min: string;
  /** The last date the server accepts. */
  max: string;
  suggested: string;
}

export function reviewDateBounds(now: Date): ReviewDateBounds {
  const today = utcDate(now);
  return { today, min: addDays(today, 1), max: addDays(today, REVIEW_MAX_DAYS), suggested: addDays(today, REVIEW_SUGGESTED_DAYS) };
}

export interface ReviewErrors {
  reason?: string;
  nextReviewBy?: string;
}

/** The same checks as the server: a reason, and a real date after today and at most 366 days ahead, in UTC. */
export function validateReview(input: { reason: string; nextReviewBy: string }, now: Date): ReviewErrors {
  const errors: ReviewErrors = {};
  const reason = input.reason.trim();
  if (!reason) errors.reason = 'A reason is required.';
  else if (reason.length > REASON_MAX) errors.reason = `The reason must be ${REASON_MAX} characters or fewer.`;
  const { today, max } = reviewDateBounds(now);
  const date = input.nextReviewBy.trim();
  if (!date) errors.nextReviewBy = 'Choose the next review date.';
  else if (!isCalendarDate(date)) errors.nextReviewBy = 'Enter a date as year-month-day, for example 2027-01-31.';
  else if (date <= today) errors.nextReviewBy = `Choose a date after today, ${today} in UTC.`;
  else if (date > max) errors.nextReviewBy = `Choose ${max} or an earlier date: the next review can be at most ${REVIEW_MAX_DAYS} days ahead.`;
  return errors;
}

/** Ties the server's validation errors to the two fields of the review form. Never throws. */
export function reviewServerErrors(detail: unknown): ReviewErrors & { other: string[] } {
  const out: ReviewErrors & { other: string[] } = { other: [] };
  if (!Array.isArray(detail)) return out;
  for (const item of detail) {
    if (typeof item !== 'object' || item === null) continue;
    const { loc, msg } = item as { loc?: unknown; msg?: unknown };
    if (typeof msg !== 'string' || !msg) continue;
    const path = Array.isArray(loc) ? loc.map(String) : [];
    if (path.includes('next_review_by')) out.nextReviewBy ??= msg;
    else if (path.includes('reason')) out.reason ??= msg;
    else out.other.push(msg);
  }
  return out;
}

export interface ReviewState {
  /** The effective review date, or an empty string when the registration names none. */
  due: string;
  overdue: boolean;
  lastReviewedAt: string | null;
  lastReviewedBy: string | null;
}

/**
 * When the registration must be reviewed next and when it last was. The effective date is the
 * latest attestation's, else the document's own. Only an approved registration can be overdue:
 * a retired one can no longer be reviewed.
 */
export function reviewState(
  record: Pick<RegistrationDetail, 'status' | 'effective_review_by' | 'last_reviewed_at' | 'last_reviewed_by' | 'document'>,
  now: Date,
): ReviewState {
  const due = (record.effective_review_by ?? record.document?.review_by ?? '').trim();
  return {
    due,
    overdue: record.status === 'APPROVED' && !!due && due < utcDate(now),
    lastReviewedAt: record.last_reviewed_at ?? null,
    lastReviewedBy: record.last_reviewed_by ?? null,
  };
}

/** What to say after a retire. The server's sentence says what retirement means and is shown as sent. */
export function retireMessage(result: Pick<ActionResult, 'outcome' | 'reason'>): string {
  if (result.outcome === 'unchanged') return 'The registration was already retired. Nothing was changed.';
  return (
    result.reason?.trim() ||
    'The registration is retired. Retirement is permanent. The agent’s runtime, if it has one, is still deployed until its pipeline removes it.'
  );
}

export function reviewMessage(nextReviewBy: string): string {
  return `Review confirmed. The next review is due by ${nextReviewBy}.`;
}

/**
 * What an action on this page has just made true of the agent, for the page to show until it is
 * left. The agents API serves these fields from a short cache, so the record read right after
 * the action can still carry the old values.
 *
 * This is what the page knows without asking: the date it sent and roughly when. Who the
 * review is recorded under is the API's to say (it records a person by an identifier they
 * cannot change, not by their display name), so no reviewer is named here. `agentFromRegistration`
 * gives the recorded facts once the registration has been read again.
 */
export function agentAfterReview(nextReviewBy: string, at: string): Partial<Agent> {
  return {
    review_by: nextReviewBy,
    last_reviewed_at: at,
    last_reviewed_by: null,
    // A patch: only this flag is settled by the action. The others stay as the API sends them.
    flags: { review_overdue: false },
  };
}

export function agentAfterRetire(): Partial<Agent> {
  return {
    lifecycle_state: 'deprecated',
    registry_status: RETIRED_STATUS,
    // A retired registration is never overdue for review. Nothing else is asserted about its
    // flags: with nothing deployed the API closes its obligations and none of them applies.
    flags: { review_overdue: false },
  };
}

/**
 * What a registration says about its agent, for the agent page. The API reads a registration
 * fresh, with its latest review, while it serves the agent from a short cache: after an action
 * the registration is read again and these facts are shown as recorded, reviewer included.
 * Null for a registration that is neither approved nor retired, about which this says nothing.
 */
export function agentFromRegistration(
  record: Pick<RegistrationDetail, 'status' | 'effective_review_by' | 'last_reviewed_at' | 'last_reviewed_by' | 'document'>,
  now: Date,
): Partial<Agent> | null {
  if (record.status === RETIRED_STATUS) return agentAfterRetire();
  if (record.status !== 'APPROVED') return null;
  const review = reviewState(record, now);
  return {
    // No effective date: the page falls back to the document's own, as the API does.
    review_by: review.due || null,
    last_reviewed_at: review.lastReviewedAt,
    last_reviewed_by: review.lastReviewedBy,
    flags: { review_overdue: review.overdue },
  };
}
