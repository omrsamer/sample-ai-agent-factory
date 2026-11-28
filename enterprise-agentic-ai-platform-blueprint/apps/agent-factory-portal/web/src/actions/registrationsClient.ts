// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import client, { ApiRequestError } from '../api/client';
import {
  fieldForDocumentPath,
  fieldForMessage,
  type FieldErrors,
  type RegistrationDocument,
  type RegistrationInput,
} from './governanceSchema';

/**
 * The actions client: every request of the governed registration and approval feature, and the
 * only module in the application that issues a write.
 *
 * It is reachable only through the screens in this folder, which the application loads only
 * when `features.governedActions` is true. Writes are POST, PUT and DELETE on `/registrations`
 * and nothing else. Registering, approving, retiring or reviewing a record produces a governance
 * record and a decision; it deploys and removes nothing. The contract is
 * `../api/ACTIONS_CONTRACT.md`.
 */

/** Registry status. Shown as recorded when this build does not know the value. */
export type RegistrationStatus =
  | 'CREATING'
  | 'DRAFT'
  | 'UPDATING'
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'REJECTED'
  | 'DEPRECATED'
  | 'CREATE_FAILED'
  | 'UPDATE_FAILED';

/** One row of `GET /registrations`, and the `registration` of an `ActionResult`. */
export interface Registration {
  record_id: string;
  name: string;
  status: string;
  /** The same status in the agent lifecycle vocabulary. `deprecated` is a retired registration. */
  lifecycle_state?: string | null;
  /** The reason of the last approve, reject or retire, shortened by the registry. */
  status_reason?: string | null;
  record_version?: string | null;
  tenant_id?: string | null;
  agent_id?: string | null;
  environment?: string | null;
  document: RegistrationDocument;
  /** Identifies exactly this document. Sent back with a decision. */
  document_sha256: string;
  created_at?: string | null;
  updated_at?: string | null;
}

/** `GET /registrations/{record_id}`: the record plus who acted on it, from the audit trail. */
export interface RegistrationDetail extends Registration {
  created_by_label?: string | null;
  submitted_by_label?: string | null;
  submitted_at?: string | null;
  /** True when the caller submitted this record and so may not decide it. */
  submitted_by_me?: boolean;
  decision?: string | null;
  decided_by_label?: string | null;
  decided_at?: string | null;
  decision_reason?: string | null;
  /** The last approved version of this record's document, when the API can supply it. */
  previous_approved?: RegistrationDocument | null;
  /** The latest attestation: a review, or an approval of a document that names a review date. */
  last_reviewed_at?: string | null;
  last_reviewed_by?: string | null;
  /**
   * When the registration must be reviewed next (YYYY-MM-DD): the latest attestation's date,
   * else the document's own. A review never changes the document.
   */
  effective_review_by?: string | null;
}

/** One event of the audit trail. */
export interface AuditEvent {
  event_id: string;
  request_id: string;
  at: string;
  phase: 'intent' | 'result' | string;
  action: string;
  outcome: 'allowed' | 'denied' | 'failed' | string;
  reason: string;
  actor_label: string;
  actor_role?: string | null;
  status_before?: string | null;
  status_after?: string | null;
  /** Set on a review, and on an approval that recorded a review date: that date. */
  next_review_by?: string | null;
  attested_at?: string | null;
  detail?: string | null;
  /** A background sweep of a contained agent (`action: "sweep"`): which one it is, 1 to 3. */
  sweep?: number | null;
  /**
   * Containment events. On a sweep `sessions_found` is every session of the last eight hours,
   * ended or not (the sweep has to try each), and `sessions_stopped` is how many were running.
   */
  sessions_found?: number | null;
  sessions_stopped?: number | null;
  /** Sweeps only: sessions that had already ended. */
  sessions_not_active?: number | null;
  sessions_failed?: number | null;
}

/** `GET /registrations/{record_id}/history`. */
export interface RegistrationHistory {
  record_id: string;
  /** Newest first. The API lists the newest events only. */
  events: AuditEvent[];
  /** True when the history holds older events than the ones listed. */
  events_truncated?: boolean;
}

/** The answer to every write. */
export interface ActionResult {
  action: string;
  /** `allowed`, or `unchanged` for the retire of a record that was already retired. */
  outcome: string;
  /** For a retire: a sentence that says what retirement means, to show the user. */
  reason: string;
  request_id: string;
  /** Null after a delete. */
  registration: Registration | null;
  /** False when the action was done but its result could not be written to the audit trail. */
  audit_complete: boolean;
}

export interface RegistrationFilters {
  status?: RegistrationStatus;
  tenant_id?: string;
}

const path = (recordId: string, suffix = '') => `/registrations/${encodeURIComponent(recordId)}${suffix}`;

export const registrationsApi = {
  list: async (filters?: RegistrationFilters): Promise<Registration[]> =>
    (await client.get<Registration[]>('/registrations', { params: filters })).data,
  get: async (recordId: string): Promise<RegistrationDetail> =>
    (await client.get<RegistrationDetail>(path(recordId))).data,
  history: async (recordId: string): Promise<RegistrationHistory> =>
    (await client.get<RegistrationHistory>(path(recordId, '/history'))).data,
  create: async (input: RegistrationInput): Promise<ActionResult> =>
    (await client.post<ActionResult>('/registrations', input)).data,
  update: async (recordId: string, input: RegistrationInput): Promise<ActionResult> =>
    (await client.put<ActionResult>(path(recordId), input)).data,
  submit: async (recordId: string): Promise<ActionResult> =>
    (await client.post<ActionResult>(path(recordId, '/submit'))).data,
  remove: async (recordId: string): Promise<ActionResult> => (await client.delete<ActionResult>(path(recordId))).data,
  /** `documentSha256` is the document the approver was shown; a changed record is refused. */
  approve: async (recordId: string, reason: string, documentSha256: string): Promise<ActionResult> =>
    (await client.post<ActionResult>(path(recordId, '/approve'), { reason, document_sha256: documentSha256 })).data,
  reject: async (recordId: string, reason: string, documentSha256: string): Promise<ActionResult> =>
    (await client.post<ActionResult>(path(recordId, '/reject'), { reason, document_sha256: documentSha256 })).data,
  /** Retires the registration for good. Nothing that is deployed is removed. */
  retire: async (recordId: string, reason: string): Promise<ActionResult> =>
    (await client.post<ActionResult>(path(recordId, '/retire'), { reason })).data,
  /** Attests that an approved registration was reviewed, and by when it must be reviewed again. */
  review: async (recordId: string, reason: string, nextReviewBy: string): Promise<ActionResult> =>
    (await client.post<ActionResult>(path(recordId, '/review'), { reason, next_review_by: nextReviewBy })).data,
};

export type ActionFailureKind = 'validation' | 'forbidden' | 'conflict' | 'not_found' | 'unavailable' | 'other';

/** A failed action, classified so every screen words it the same way. */
export interface ActionFailure {
  kind: ActionFailureKind;
  /** Heading for the message. */
  title: string;
  /** The server's own explanation, shown as sent. */
  message: string;
  /** The server's advice on what to do instead, when it sent one. */
  hint: string | null;
  /** Reference of the refusal in the audit trail, when it was recorded. */
  requestId: string | null;
  /** Validation errors by form field. Empty unless `kind` is `validation`. */
  fieldErrors: FieldErrors;
  /** Validation errors that could not be tied to a field. */
  otherErrors: string[];
}

export const FORBIDDEN_TITLE = 'You do not hold the authority for this action';
export const CONFLICT_TITLE = 'This cannot be done in the current state';

function stringField(body: unknown, key: string): string | null {
  if (typeof body !== 'object' || body === null) return null;
  const value = (body as Record<string, unknown>)[key];
  return typeof value === 'string' && value.trim() ? value : null;
}

/** Turns whatever a request threw into an `ActionFailure`. Total: never throws. */
export function classifyFailure(err: unknown, fallback: string): ActionFailure {
  const base = { hint: null, requestId: null, fieldErrors: {} as FieldErrors, otherErrors: [] as string[] };
  if (!(err instanceof ApiRequestError)) {
    return { ...base, kind: 'other', title: fallback, message: err instanceof Error ? err.message : '' };
  }
  const message = err.message;
  const extras = { hint: stringField(err.body, 'hint'), requestId: stringField(err.body, 'request_id') };
  switch (err.status) {
    case 403:
      return { ...base, ...extras, kind: 'forbidden', title: FORBIDDEN_TITLE, message };
    case 409:
      return { ...base, ...extras, kind: 'conflict', title: CONFLICT_TITLE, message };
    case 404:
      return { ...base, kind: 'not_found', title: 'This record no longer exists', message };
    case 503:
      return { ...base, kind: 'unavailable', title: 'Nothing was changed', message };
    case 502:
      // The server's sentence says what was and was not done; it is shown as sent.
      return { ...base, ...extras, kind: 'other', title: 'The action failed part-way', message };
    case 422: {
      const fieldErrors: FieldErrors = {};
      const otherErrors: string[] = [];
      if (Array.isArray(err.detail)) {
        for (const item of err.detail) {
          const field = fieldForDocumentPath(item.loc ?? []);
          if (field && !fieldErrors[field]) fieldErrors[field] = item.msg;
          else if (!field) otherErrors.push(item.msg);
        }
      } else if (message) {
        const field = fieldForMessage(message);
        if (field) fieldErrors[field] = message;
        else otherErrors.push(message);
      }
      return { ...base, kind: 'validation', title: 'The server did not accept this record', message: '', fieldErrors, otherErrors };
    }
    default:
      return { ...base, kind: 'other', title: fallback, message };
  }
}
