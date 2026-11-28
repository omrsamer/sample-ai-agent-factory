# Agent Factory Portal: registration, approval and lifecycle contract

Endpoints for registering agent records in the platform AWS Agent Registry,
deciding on them, and what happens to a registration after approval: retiring
it, attesting its periodic review, and downloading one evidence document per
agent. Four read endpoints are part of the read API; eight write endpoints are
served by two separate functions, each with its own IAM role.

What is new for the lifecycle is collected in
[Lifecycle after approval](#lifecycle-after-approval). The rest of this
document is unchanged except where it says so.

All paths are under `/api/v1`. Every request carries `Authorization: Bearer <token>`
as for the read API. Write requests with a body send `Content-Type: application/json`.

## Who may do what

| Portal role (`portal_role` on `/users/me`) | Registrar | Approver | Tenants |
| --- | --- | --- | --- |
| `platform` | yes | yes | every tenant |
| `developer` | yes | no | tenants of the caller's groups |
| `approver`, `security` | no | yes | tenants of the caller's groups |
| `sre`, `finops`, `readonly` | no | no | none |

`GET /users/me` now also returns:

- `authorities: string[]` with the values `registrar` and `approver` (and the
  same facts as booleans, `can_register` and `can_approve`);
- `registration_tenants: string[] | null` (`["*"]` means every tenant; `null`
  means the read API was not given the tenant map, so the front end cannot
  pre-filter);
- `name`: the label to display. It is the token's name, else the email, else
  the user name, and only as a last resort the subject id. `oid` is the
  subject id, the same value as `submitted_by` and `actor_subject`.

Use them to decide what to offer. The action functions enforce the rules themselves.

Retire and review use the approver authority: offer them to a caller whose
`authorities` include `approver` (`can_approve`) and whose
`registration_tenants` include the record's tenant or `"*"`. `/users/me` has no
new field for them.

Rules the functions enforce (the reason text is returned in `detail`):

- Create, update, submit and delete need the registrar authority and a tenant the caller holds.
- Approve and reject need the approver authority and a tenant the caller holds.
- Retire and review need the approver authority and a tenant the caller holds
  (`RET-01-N`, `RET-02-N`, `REV-01-N`, `REV-02-N`). Retire has no two-person
  rule: the person who registered, submitted or approved a record may retire
  it.
- The person who submitted a record cannot attest its review, even with the
  `platform` role (`REV-05-N`): a review is a second pair of eyes, as an
  approval is. A record the portal knows no submitter of can be attested by
  any approver of its tenant.
- A record's review can be attested once in 24 hours (`REV-06-N`, 409). An
  approval is not counted.
- A retired record is final. Approve, reject, update and submit are refused
  with 409 (`RET-03-N`).
- The person who submitted a record cannot approve or reject it, even with the
  `platform` role (`REG-11-N`). The submitter is whoever last submitted it through the portal.
- On an APPROVED record, an update that changes `runtime_arn`, `gateway_arn`,
  `subscribed_tool_ids`, `risk_class` or `data_classification` is refused
  (`REG-12-N`, with a `hint`). Register a new record instead. `sponsor` and
  `review_by` are not governed: changing them is an ordinary update.
- A registration cannot name another tenant's resources (`REG-13-N`, with a
  `hint`). A `runtime_arn`, `gateway_arn` or `policy_engine_arn` that points
  into an account and Region where the portal has cells must point into a
  cell of the registration's own tenant. A resource in an account and Region
  with no cell can be named: that is how an agent detected in an account the
  portal does not manage gets registered. The rule is checked on create, on
  update, and again on approve; it holds for the `platform` role too.
- In an account and Region that several tenants share, the place does not
  say whose a resource is. A registration that names one there needs its
  registrar (on create and update) and its approver (on approve) to hold
  every tenant hosted there (`REG-13-N` as well; the `platform` role holds
  every tenant). Otherwise two people of one tenant could register another
  tenant's Runtime as their own.
- `review_by` may be at most 366 days ahead when a registration is created
  or updated (422 on `review_by`). An approval records that date, or the
  approval date plus 366 days when the document names a later one.

## Record status

Statuses are the registry's own: `CREATING`, `DRAFT`, `UPDATING`,
`PENDING_APPROVAL`, `APPROVED`, `REJECTED`, `DEPRECATED` (and `CREATE_FAILED`,
`UPDATE_FAILED`).

| Action | Allowed when the record is | Status afterwards |
| --- | --- | --- |
| create | (new) | `DRAFT` |
| update | `DRAFT`, `PENDING_APPROVAL`, `REJECTED`, `APPROVED` | `DRAFT`, always |
| submit | `DRAFT` | `PENDING_APPROVAL` |
| approve | `PENDING_APPROVAL` | `APPROVED` |
| reject | `PENDING_APPROVAL` | `REJECTED` |
| delete | anything except `APPROVED` | deleted |
| retire | anything except `DEPRECATED` (a retired record answers `unchanged`) | `DEPRECATED`, for good |
| review | `APPROVED` | `APPROVED`: the record is not touched |

`DEPRECATED` is terminal in the registry. The portal calls a `DEPRECATED`
registration retired; its `lifecycle_state` is `deprecated`. A retired record
can only be deleted.

Consequences to show in the UI:

- **Any update returns the record to `DRAFT`**, including an update of an
  approved or pending record. It must be submitted and approved again. Warn
  before saving a change to an approved record.
- **A rejected record cannot be submitted again as it is.** Update it first
  (which makes it `DRAFT`), then submit.
- **Retirement cannot be undone.** Ask for confirmation before sending it.
- **An approved registration cannot be edited to record a review**, because
  the edit would return it to `DRAFT`. Use the review attestation instead.

`CREATING` and `UPDATING` last about a second. The write endpoints wait for
them to pass before answering, so a response normally shows a settled status.

## Types

```ts
interface Registration {
  record_id: string;               // 12 letters and digits
  name: string;                    // "agent-<tenant_id>-<agent_id>-<environment>"
  status: string;                  // registry status, see above
  // The same status in the agent lifecycle vocabulary (new):
  lifecycle_state: "proposed" | "pending_approval" | "approved" | "rejected" | "deprecated";
  status_reason: string | null;    // the reason of the last approve, reject or retire, cut to 255 characters
  record_version: string | null;   // semantic version, set by the server
  tenant_id: string | null;
  agent_id: string | null;
  environment: string | null;      // "nonprod" | "prod"
  document: RegistrationDocument;  // the governance document, snake_case
  document_sha256: string;         // 64 hex characters; identifies exactly this document
  created_at: string | null;       // ISO 8601 UTC
  updated_at: string | null;
}

interface RegistrationDocument {
  schema_version: "agenticai.agent-governance/1.0";
  tenant_id: string;
  agent_id: string;
  environment: "nonprod" | "prod";
  owner_group: string;
  business_purpose: string;
  risk_class: "minimal" | "limited" | "high" | "unacceptable";
  data_classification: "public" | "internal" | "confidential" | "restricted";
  cost_centre: string;
  record_version: string;
  application_id?: string;
  contact?: string;
  sponsor?: string;                // the accountable person (name or email)
  review_by?: string;              // YYYY-MM-DD: when the registration must be reviewed again
  framework?: string;
  golden_path?: { name: string; version: string };
  runtime_arn?: string;
  gateway_arn?: string;
  memory_id?: string;
  subscribed_tool_ids?: string[];  // sorted, unique
  policy_engine_arn?: string;
  policy_engine_mode?: "NONE" | "LOG_ONLY" | "ENFORCE";
  source_revision?: string;
  evaluation?: { verdict: "passed" | "failed" | "not_run"; run_id?: string; completed_at?: string };
}

// Body of create and update: the document's fields in snake_case, without schema_version.
interface RegistrationInput {
  tenant_id: string;               // ^[a-z0-9][a-z0-9-]{0,62}$
  agent_id: string;                // ^[a-z0-9][a-z0-9-]{0,62}$
  environment: "nonprod" | "prod";
  owner_group: string;             // 1 to 256 characters
  business_purpose: string;        // 1 to 2000 characters
  risk_class: "minimal" | "limited" | "high" | "unacceptable";
  data_classification: "public" | "internal" | "confidential" | "restricted";
  cost_centre: string;             // 1 to 128 characters
  application_id?: string | null;  // 1 to 128 characters
  contact?: string | null;         // 1 to 256 characters
  sponsor?: string | null;         // 1 to 256 characters; the accountable person
  review_by?: string | null;       // YYYY-MM-DD, a real calendar date, and at most 366 days ahead
  framework?: string | null;       // up to 64 characters
  golden_path?: { name: string; version: string } | null;
  runtime_arn?: string | null;     // an AgentCore runtime ARN
  gateway_arn?: string | null;     // an AgentCore gateway ARN
  memory_id?: string | null;
  subscribed_tool_ids?: string[] | null;   // each ^[a-z0-9][a-z0-9-]{0,62}$
  policy_engine_arn?: string | null;
  policy_engine_mode?: "NONE" | "LOG_ONLY" | "ENFORCE" | null;
  source_revision?: string | null;
  evaluation?: { verdict: "passed" | "failed" | "not_run"; run_id?: string | null; completed_at?: string | null } | null;
  record_version?: string | null;  // optional, see each endpoint
}

interface ActionResult {
  action: "create" | "update" | "submit" | "delete" | "approve" | "reject" | "retire" | "review";
  outcome: "allowed" | "unchanged";  // "unchanged": retire of a record that was already retired
  // Why it was allowed. For approve, reject and review: the person's own reason.
  // For retire: a sentence that says what retirement means, to show the user.
  reason: string;
  request_id: string;              // ties the response to its audit events
  registration: Registration | null;  // null after a delete
  // false: the action was done, but its result event (or, for an approval, the record of its
  // review date) could not be written
  audit_complete: boolean;
}

// GET /registrations/{record_id} only. The list returns plain Registration objects.
interface RegistrationDetail extends Registration {
  created_by: string | null;           // subject id; null for a record not created through the portal
  created_by_label: string | null;
  submitted_by: string | null;         // set while PENDING_APPROVAL, APPROVED or REJECTED
  submitted_by_label: string | null;
  submitted_at: string | null;
  submitted_by_me: boolean;            // the caller is the submitter: approve and reject will be refused
  decision: "approve" | "reject" | null;   // set while APPROVED or REJECTED
  decided_by_label: string | null;
  decided_at: string | null;
  decision_reason: string | null;      // the approver's full reason (status_reason is cut to 255 characters)
  previous_approved: RegistrationDocument | null;  // the document as last approved through the portal; null if never
  // New. The latest attestation: a review, or an approval of a document that names review_by.
  // Both null when there is none.
  last_reviewed_at: string | null;     // ISO 8601 UTC
  last_reviewed_by: string | null;     // the reviewer's or approver's label
  // New. When the registration must be reviewed next: the latest attestation's date, else
  // document.review_by, else null. document.review_by itself is never changed by a review.
  effective_review_by: string | null;  // YYYY-MM-DD
}

interface AuditEvent {
  event_id: string;
  request_id: string;              // the intent and result of one action share it
  at: string;                      // ISO 8601 UTC, microseconds
  phase: "intent" | "result";
  action: "create" | "update" | "submit" | "delete" | "approve" | "reject" | "retire" | "review";
  outcome: "allowed" | "denied" | "failed" | "unchanged";
  reason: string;                  // on the result of an approve, reject, retire or review: the person's reason
  actor_subject: string;           // the person's identity: every rule compares this, and only this
  actor_label: string;             // a label to read beside the subject: a verified or directory-set email or user name, else the subject. It can change for the same person. Never the display name
  actor_role: string;              // portal role at the time
  tenant_id: string | null;
  record_id: string | null;        // null for a create that had no record yet
  record_name: string | null;
  document_sha256: string | null;
  status_before: string | null;
  status_after: string | null;     // "DELETED" after a delete
  // Set on a review, and on the result of an approval that recorded a review date:
  next_review_by: string | null;   // that date
  attested_at: string | null;      // result events only: when it was recorded; equals last_reviewed_at
  detail: string | null;           // the result event of a retire: what retirement means
}

interface RegistrationHistory {
  record_id: string;
  events: AuditEvent[];            // the newest 200 events of the record's history, newest first
  events_truncated: boolean;       // true: the history holds older events that are not listed
}

interface ErrorBody {
  detail: string | { loc: string[]; msg: string; type: string }[];
  action?: string;                 // present on 403 and 409 from an action
  request_id?: string;             // present on 403 and 409 from an action: the id of the refusal in the record's history, or in the function's log when it is not written there (see the history endpoint)
  hint?: string;                   // present on REG-12-N and REG-13-N
}

// Body of retire.
interface RetireInput {
  reason: string;                  // required, 1 to 1000 characters
}

// Body of a review attestation.
interface ReviewInput {
  reason: string;                  // required, 1 to 1000 characters
  next_review_by: string;          // YYYY-MM-DD, after today (UTC) and at most 366 days ahead
}
```

Unknown fields in a request body are rejected with 422. Optional fields may be
omitted or null; an empty string is treated as absent.

## Read endpoints (read API, any mapped role)

### `GET /registrations`

Query: `status?` one of `DRAFT`, `PENDING_APPROVAL`, `APPROVED`, `REJECTED`,
`DEPRECATED`; `tenant_id?`. Returns `Registration[]`, most recently updated
first. Only agent governance records are listed (tool records are not).
The list is read fresh on every request, so it reflects an action that just completed.

Status codes: 200; 401; 403 (no mapped group); 422 (bad query value); 502 (registry unavailable).

### `GET /registrations/{record_id}`

Returns `RegistrationDetail`: the registration plus who created, submitted and
decided it, read from the audit trail. Use it for the detail page and to
refresh after a 409. The people fields are null for a record that did not go
through the portal (for example one published by a pipeline).

The detail reads the newest 2000 events of the record's history, and the
record's oldest events for who created it. In a history longer than that, a
people field can be null although the event exists further back.

`previous_approved` is the document as it was at the latest approval made
through the portal, for showing an approver what changed. The registry keeps
only the current document, so the portal stores the approved document with the
approval's audit event. It is null when the record was never approved through
the portal, including records approved before this was introduced or approved
outside the portal. While the record is `APPROVED` and unchanged it equals `document`.

Status codes: 200; 401; 403; 404 (no such record, or not an agent governance
record); 422 (malformed id); 502.

### `GET /registrations/{record_id}/history`

Returns `RegistrationHistory`: the newest 200 events of the record's history,
newest first. `events_truncated` is true when the history holds older ones;
say so under the list. Works for a deleted record. An allowed action appears
as two events with the same `request_id`: an `intent` written before the
action and a `result` written after it (`allowed`, or `failed` if the registry
refused). A denied action is one `result` event with `outcome: "denied"`.
Refused creations of a record with the same name (409) are included. Retire
and review events are there too. A review carries `next_review_by`; a retire
of a record that was already retired is one `result` event with
`outcome: "unchanged"`.

**Who writes into a record's history.** Only a caller who has a part in the
record: the authority the action needs, and the record's tenant. A refusal of
such a caller is in the history: separation of duties (`REG-11-N`),
`REG-12-N`, `REG-13-N` on update and approve, and a status that does not
permit the action.

Every other refusal is answered with 403 and a `request_id`, and kept in the
function's log under that id. It is **not** in a history:

- An attempt by a caller without the needed authority. It is refused before
  the record is read, so its event would be keyed by whatever id the caller
  sent.
- An attempt by a caller who holds the authority but not the record's tenant
  (`"cross-tenant update is denied"`, `RET-02-N`, `REV-02-N` and the like).
  The record was read, but the caller has no part in it.
- A create that is refused for authority, for the tenant or by `REG-13-N`. No
  record exists yet, and the name is the caller's.

The reason is the same for all three: a history is never shortened, so if
such refusals were written, anyone signed in could fill the history of a
record of another tenant with them. A history therefore shows fewer refusals
than before this rule.

Status codes: 200; 401; 403; 404 (no events for this id); 422 (malformed id);
500 (the read API has no audit table configured).

## Registrar endpoints (registrar function)

Authority: registrar, and the caller must hold the record's tenant.

### `POST /registrations`

Body: `RegistrationInput`. `record_version` defaults to `1.0.0`.
Returns 201 with `ActionResult`; `registration.status` is `DRAFT`.

### `PUT /registrations/{record_id}`

Body: `RegistrationInput`, the complete new document (not a patch).
`tenant_id`, `agent_id` and `environment` must equal the record's.
`record_version`: omit it and the server raises the patch number; supply it and
it must be higher than the current version.
Returns 200 with `ActionResult`; `registration.status` is `DRAFT`.

### `POST /registrations/{record_id}/submit`

No body. Returns 200 with `ActionResult`; `registration.status` is `PENDING_APPROVAL`.

### `DELETE /registrations/{record_id}`

No body. Returns 200 with `ActionResult`; `registration` is `null`.

## Approver endpoints (approver function)

Authority: approver, the caller must hold the record's tenant, and the caller
must not be the record's submitter.

The approver function also serves retire and review. Retire has no submitter
rule; review has one of its own (`REV-05-N`). They are specified under
[Lifecycle after approval](#lifecycle-after-approval).

### `POST /registrations/{record_id}/approve` and `POST /registrations/{record_id}/reject`

Body:

```ts
interface DecisionInput {
  reason: string;             // required, 1 to 1000 characters
  document_sha256?: string;   // optional: Registration.document_sha256 of what the approver reviewed
}
```

Send `document_sha256` from the registration the approver was shown. If the
record changed in the meantime the decision is refused with 409 instead of
being applied to a document nobody reviewed.

Returns 200 with `ActionResult`; `registration.status` is `APPROVED` or
`REJECTED`. The full reason is kept in the audit trail; `status_reason` on the
record holds its first 255 characters.

**The submitter is read from the record's history,** back from its newest
event to its latest submit, and at most 2000 events. If the submit is not
among them, the decision is refused with 409 and nothing is changed: who
submitted the record is not known, and that must not read as "nobody the
portal knows". Updating the record and submitting it again puts a new submit
at the top of its history.

An approval counts as a review. When the approved document names `review_by`,
the approval is also recorded as a review with that date and the approver as
the reviewer (see [the effective review date](#the-effective-review-date)).
The registry's answer cannot be taken back, so if that record cannot be
written the approval still stands and the response has `audit_complete: false`.
A document with no `review_by`, and a rejection, record no review.

## Lifecycle after approval

Three things: retire a registration, attest its periodic review, and download
one evidence document per agent. Retire and review are served by the approver
function; the evidence document by the read API.

### `POST /registrations/{record_id}/retire` (approver function)

Body: `RetireInput`. Sets the record's status to `DEPRECATED`. The registry
never undoes that.

Returns 200 with `ActionResult`:

- `outcome: "allowed"`: the record was retired. `registration.status` is
  `DEPRECATED`, `registration.lifecycle_state` is `deprecated`, and
  `registration.status_reason` holds the first 255 characters of the reason
  (the full reason is in the audit trail). `reason` is this text, to show the
  user: "The registration is retired. Retirement is permanent: the record can
  no longer be approved, rejected, updated or submitted. The agent's Runtime,
  if it has one, is still deployed until its pipeline removes it."
- `outcome: "unchanged"`: the record was already retired and nothing was
  changed. `reason` starts with "The registration was already retired; nothing
  was changed." This is not an error.

What to show:

- Offer retire on every registration that is not `DEPRECATED`, in any status,
  to a caller with the approver authority for the record's tenant.
- Confirm first, and say both things: it cannot be undone, and it does not
  remove anything that is deployed. The portal never deletes a Runtime.
- Afterwards the agent keeps appearing in `/agents` with
  `lifecycle_state: "deprecated"`. What else it shows depends on whether its
  Runtime is still there:
  - **Still deployed** (a detection source sees its Runtime):
    `flags.unmanaged: true`, the risk reason `REGISTRATION_DEPRECATED` (high),
    "The agent's registration is retired (DEPRECATED) and its Runtime is
    still deployed.", and every other reason that applies. Someone still has
    to remove the Runtime.
  - **Nothing deployed** (no Runtime known): `obligations_closed: true`. No
    risk rule applies (`risk.level` is `low`, `risk.reasons` is empty), and
    `flags.unmanaged`, `flags.ownerless`, `flags.review_overdue` and
    `flags.inactive` are null because they do not apply. Retirement is
    terminal, so nothing about the record could ever be corrected. Show such
    an agent as retired, with no risk badge and no flag chips, and do not
    word its null flags as "unknown". It is in no flag count of
    `/fleet/summary` (neither `flags` nor `flags_unknown`) and never in
    `needs_attention`.
  - **Not known for the moment** (the reader of the Runtime's account could
    not be used, `reader_status: "unreachable"`): `obligations_closed` stays
    false, and the agent has the flags and reasons of any registered agent
    whose Runtime could not be read. It is closed, or gets
    `REGISTRATION_DEPRECATED`, once the reader answers again.
- On a retired registration do not offer approve, reject, edit, submit or
  review. They answer 409. Delete stays available to a registrar, as for any
  record that is not approved, and the history of a deleted record remains.

| Code | When | `detail` |
| --- | --- | --- |
| 200 | Retired, or already retired (`outcome`) | (an `ActionResult`) |
| 403 | The caller lacks the approver authority (answered before the record is read) | `"retire requires the approver authority; principal holds the '<role>' role (RET-01-N)"` |
| 403 | The caller does not hold the record's tenant | `"the record belongs to a tenant the principal does not hold (RET-02-N)"` |
| 404 | No such registration, or not an agent governance record | `"Registration not found"` |
| 409 | The record is still being created or updated after a bounded wait | `"the record is still being created or updated; try again shortly (RET-04-N)"` |
| 409 | The registry refused the status change | `"The registry refused the action for the record's current state"` |
| 422 | `reason` missing, empty or longer than 1000 characters; an unknown field | A list of field errors |

### What a retired record refuses

The registrar and approver functions refuse these by rule, before any call to
the registry, and write the refusal to the audit trail:

| Request on a retired record | Code | `detail` |
| --- | --- | --- |
| `POST .../approve` | 409 | `"a retired record cannot be approved: retirement is permanent (RET-03-N)"` |
| `POST .../reject` | 409 | `"a retired record cannot be rejected: retirement is permanent (RET-03-N)"` |
| `PUT /registrations/{record_id}` | 409 | `"a retired record cannot be updated: retirement is permanent (RET-03-N)"` |
| `POST .../submit` | 409 | `"a retired record cannot be submitted: retirement is permanent (RET-03-N)"` |
| `POST .../review` | 409 | `"only an approved registration can be attested; this one is DEPRECATED (REV-03-N)"` |
| `POST .../retire` | 200 | `outcome: "unchanged"` |
| `DELETE /registrations/{record_id}` | 200 | Deleted, as before |

The authority and tenant rules still come first: a caller who may not take the
action at all gets the same 403 as on any other record. For an update, the
refusal comes before the document is checked against the schema, so an update
whose only fault is a document value (for example an unknown `risk_class`)
answers 409 too. A malformed body (a missing field, a wrong type, an unknown
field) is a 422 as on every route.

### `POST /registrations/{record_id}/review` (approver function)

Body: `ReviewInput`. Records that the caller reviewed the approved
registration and by when it must be reviewed again. Nothing in the registry is
changed: the record stays `APPROVED`, its document and `updated_at` stay as
they are. The attestation is kept in the audit trail and is append-only.

Returns 200 with `ActionResult`: `action` is `review`, `reason` is the
reviewer's reason, `registration` is the unchanged registration.

#### The effective review date

One rule: the latest attestation wins. There are two kinds of attestation.

| Kind | Made by | Its date |
| --- | --- | --- |
| `approval` | `POST .../approve`, when the approved document names `review_by` | The document's `review_by`, or the approval date plus 366 days when the document names a later date |
| `review` | `POST .../review` | `next_review_by` from the request, at most 366 days ahead |

So after an approval the date is the document's own; a later review moves it;
a later re-approval of a changed document moves it again to that document's
`review_by`. A re-approval of a document with no `review_by` records nothing,
so the earlier date stays. Changing `review_by` in a document has no effect
until that document is approved. A registration with no attestation at all
(for example one approved outside the portal) shows its document's
`review_by`.

The read API reports the effective date as:

- `review_by` on an agent (`GET /agents`, `GET /agents/{id}`), together with
  `last_reviewed_at` and `last_reviewed_by` (the time and the person of the
  latest attestation of either kind; both null when there is none);
  `flags.review_overdue` and the risk reason `REVIEW_OVERDUE` ("The agent's
  review date has passed.") follow it. `governance.review_by` on the agent is
  still the document's own date.
- `effective_review_by`, `last_reviewed_at` and `last_reviewed_by` on
  `GET /registrations/{record_id}`. `document.review_by` there is the stored
  document's own date and does not change.

A retired registration is never `review_overdue`, whatever its date: it can no
longer be reviewed. With nothing deployed the flag is null, like the other
flags that no longer apply (`obligations_closed`, above).

The inventory export (`GET /agents/export`) has two more columns, added at the
end: `review_by` (the effective date) and `last_reviewed_at`.

`GET /fleet/summary` has a new field, `review_attestations`: `"ok"`,
`"disabled"` (the read API has no audit table configured) or an error code. If
the attestations cannot be read, the inventory is still served, every review
date shown is the registration's own, and `warnings` says so.

What to show:

- Offer it on an `APPROVED` registration to a caller with the approver
  authority for the record's tenant, unless the caller is the record's
  submitter (`submitted_by_me` on `GET /registrations/{record_id}`): that
  caller gets `REV-05-N`.
- After a review, another one is refused for 24 hours (`REV-06-N`). The
  `detail` names the time of the last attestation; `last_reviewed_at` on the
  registration is that time when the latest attestation is a review.
- Limit the date input to tomorrow through today plus 366 days, both counted
  in UTC. The server checks the same bounds.
- After a 200, read `GET /registrations/{record_id}` again: it shows the new
  `last_reviewed_at`, `last_reviewed_by` and `effective_review_by` at once.
  The agent list shows the new `review_by` after the read API's cache lifetime
  (30 seconds by default), not instantly.
- The page of the one agent, `GET /agents/{agent_id}`, does not wait for the
  cache after a decision. When a decision about the agent that was carried
  out (a registration action or a contain or release with outcome `allowed`
  or `unchanged`) is newer than the cached inventory, that read loads the
  inventory again and answers from it: status, flags and risk then agree
  with the registration read from the registry. The load happens at most
  once in 15 seconds per execution environment, shared with the evidence
  document; inside that time the answer is the cached one. The list,
  `GET /agents`, stays cached.

| Code | When | `detail` |
| --- | --- | --- |
| 200 | Attested | (an `ActionResult`) |
| 403 | The caller lacks the approver authority (answered before the record is read) | `"a review attestation requires the approver authority; principal holds the '<role>' role (REV-01-N)"` |
| 403 | The caller does not hold the record's tenant | `"the record belongs to a tenant the principal does not hold (REV-02-N)"` |
| 404 | No such registration, or not an agent governance record | `"Registration not found"` |
| 409 | The record is not `APPROVED` | `"only an approved registration can be attested; this one is <STATUS> (REV-03-N)"` |
| 422 | `reason` or `next_review_by` missing or malformed; an unknown field | A list of field errors |
| 422 | The date is not a calendar date, is not after today (UTC), or is more than 366 days ahead | One error with `loc: ["body", "next_review_by"]`, `type: "review_date"` and a `msg` that ends in `(REV-04-N)`, for example `"next_review_by must be after today, 2026-11-27 in UTC (REV-04-N)"` |
| 403 | The caller is the record's submitter | `"the submitter cannot attest the review of its own record - separation of duties (REV-05-N)"` |
| 409 | The record's review was attested less than 24 hours ago | `"a registration's review can be attested once in 24 hours; this one was attested at <time> (REV-06-N)"` |
| 409 | The record's history holds more than 2000 events since its latest submit or in the last 24 hours, so the two rules above could not be checked | A sentence to show the user. Nothing was attested |
| 503 | The attestation could not be written, so nothing was attested | `"The review could not be recorded, so nothing was attested"` |

The checks run in the order of the table: an unauthorized caller gets 403 and a
record that is not approved gets 409 whatever date was sent. `REV-05-N` and
`REV-06-N` are written to the record's history once for each person and logged
after that; the 403 and the 409 carry `request_id` either way.

### `GET /agents/{agent_id}/evidence` (read API, any mapped role)

One JSON document about one agent, for an auditor. It is a download:

- `Content-Type: application/json`
- `Content-Disposition: attachment; filename="agent-evidence-<agent name>-<UTC date>.json"`.
  The name holds only letters, digits, `.`, `_` and `-`. The header is exposed
  to cross-origin scripts, as for the inventory export.
- `Cache-Control: no-store`

Fetch it with the bearer token like any other read, then save the body under
the file name from the header. `agent_id` is `Agent.id`, for a registered or
an unregistered agent alike.

Status codes: 200; 401; 403 (no mapped group); 404 (`"Agent not found"`); 422
(malformed id). A part that cannot be read never fails the request: the
section is left empty or null and `limitations` says why.

```ts
interface AgentEvidence {
  schema_version: "agenticai.agent-evidence/1.0";
  generated_at: string;                 // ISO 8601 UTC
  generated_by: { label: string; role: string };   // the caller
  portal_environment: "nonprod" | "prod";
  agent: {
    id: string;
    name: string;
    tenant_id: string | null;
    environment: string | null;
    account_alias: string | null;       // the configured alias, else "account-" and the last four digits
    region: string | null;
    runtime_arn: string | null;
    lifecycle_state: string;
    inventory_state: "registered_and_detected" | "registered_only" | "detected_only";
    detection_sources: string[];
    reader_status: "ok" | "unreachable" | "none";
    inbound_authorizer: "AWS_IAM" | "CUSTOM_JWT" | null;
  };
  registration: {                        // null for an agent with no registration
    record_id: string;
    record_name: string | null;
    status: string;
    status_reason: string | null;
    record_version: string | null;
    document: Record<string, unknown>;  // the governance document exactly as stored (camelCase keys)
    document_sha256: string;            // the same value as document_sha256 on the audit events
    created_at: string | null;
    updated_at: string | null;
  } | null;
  decisions: AuditEvent[];              // the newest 200 audit events of the registration, oldest first
  decisions_truncated: boolean;         // true: the registration's history holds older events that are not listed
  reviews: {
    effective_review_by: string | null;
    // Where the date comes from: the latest attestation (a review: "attestation"; an approval:
    // "approval"), else the document itself ("registration").
    source: "attestation" | "approval" | "registration" | "none";
    registration_review_by: string | null;   // review_by of the document itself
    overdue: boolean | null;            // null for an agent with no registration
    attestations: {                     // oldest first
      kind: "review" | "approval";
      at: string;
      reviewed_by: string;              // subject id
      reviewed_by_label: string;
      reviewed_by_role: string | null;
      next_review_by: string;
      reason: string | null;
      request_id: string | null;        // the request_id of the review's or approval's events in decisions
    }[];
  };
  containment: {
    state: "contained" | "not_contained" | "unknown";
    detail: string | null;              // why the state is unknown; or, with not_contained, that a statement with the portal's Sid is in the policy but does not deny invocation
    // The incident record (who contained the agent, why, and the events) is shown only to a
    // caller whose role can contain or release (security, platform, sre), as in the containment
    // view. For any other caller this is false, those fields are null or empty, and limitations
    // says so.
    details_shown: boolean;
    contained_by: string | null;
    contained_by_label: string | null;
    contained_at: string | null;
    reason: string | null;
    partial: boolean;
    // The background sweeps of the containment that holds (CONTAINMENT_CONTRACT.md): how many
    // it scheduled, how many of those have run, and since when no session the portal can find
    // is running (null until a complete sweep has run after the contain's delay).
    sweeps_scheduled: number;
    sweeps_done: number;
    quiet_at: string | null;
    // A change to the Runtime's policy is not enforced at once. These say how long a contain,
    // and a release, can take to apply everywhere, and `timing` says the same in a sentence.
    enforcement_delay_seconds: number;
    release_delay_seconds: number;
    timing: string;
    // The containment events, oldest first. They carry the containment fields too
    // (agent_id, runtime_arn, sessions_found, sessions_stopped, sessions_failed, detail), and
    // the events of background sweeps (action "sweep") carry the fields listed for them in
    // CONTAINMENT_CONTRACT.md. At most the newest 200.
    events: AuditEvent[];
    events_truncated: boolean;          // true: the Runtime's history holds older events that are not listed
  };
  risk: {
    level: "low" | "medium" | "high" | "critical";
    reasons: { code: string; severity: string; detail: string }[];
    flags: Record<"unmanaged" | "ownerless" | "review_overdue" | "inactive" | "contained", boolean | null>;
    obligations_closed: boolean;        // true for a retired registration with nothing deployed: no rule applies, and the null flags mean "does not apply"
    assessed_at: string;                // the moment the agent, registration, reviews and risk sections describe, to the microsecond
  };
  policy: {                             // one entry per Tool Gateway the agent is linked to
    gateway_id: string;
    gateway_name: string | null;
    link_source: "registry" | "runtime_env" | "tags";
    policy_mode: "enforce" | "log_only" | "none" | null;   // null: the gateway could not be read
    policy_count: number | null;        // null: the policies could not be read
    cedar_sha256: string | null;        // see below; null when there is no policy or it could not be read
    policies: { policy_id: string; name: string | null; status: string | null; effect: "allow" | "deny"; sha256: string }[];
  }[];
  release: {                            // null when the agent's cell names no pipeline, or it has no execution
    pipeline_name: string | null;
    execution_id: string;
    status: string;                     // the pipeline execution's status
    evaluation_gate_result: "passed" | "failed" | "running" | "error";   // error: the gate did not run
    evaluation_gate_status: string | null;
    evaluation_gate_summary: string | null;
    source_revision: string | null;
    started_at: string;
    finished_at: string | null;
  } | null;
  limitations: string[];                // what could not be read and why; empty when everything was read
}
```

Notes for whoever reads the document:

- Every section is always present. An agent with no registration has
  `registration: null`, no decisions and no attestations.
- `policy[].policies[].sha256` is the SHA-256 of that policy's Cedar statement
  exactly as deployed. `cedar_sha256` is the SHA-256 of all of the gateway's
  statements in ascending `policy_id` order, each followed by one newline. The
  Cedar text itself is never in the document.
- `decisions` and `containment.events` hold the newest 200 events of their
  history. When a history holds more, `decisions_truncated` or
  `containment.events_truncated` is true and `limitations` says so.
- `containment.state` is `contained` only when the Runtime's policy holds the
  statement the portal writes, recognised by all of it and not by its Sid
  (CONTAINMENT_CONTRACT.md). With a statement under the portal's Sid that
  does not deny invocation, the state is `not_contained` and
  `containment.detail` says so.
- `containment.state` is what the Runtime's resource policy says. The service
  applies a change to that policy host by host, so right after a contain some
  calls can still succeed, and right after a release some can still be
  refused. The section states both delays (the same figures as
  `enforcement_delay_seconds` and `release_delay_seconds` in
  CONTAINMENT_CONTRACT.md); compare them with the times of its events.
- The agent, registration, reviews and risk sections come from one inventory,
  which describes the moment `risk.assessed_at`. The events are read when the
  document is made. If an event is newer than that moment, the inventory is
  loaded again before the document is built, so a decision taken a moment ago
  is reflected in every section. Only the result of a decision that was
  carried out counts as such an event (`allowed` or `unchanged`; not a
  refusal, a failure, an intent or a background sweep), and the inventory is
  loaded again for a document at most once in 15 seconds. `limitations` says
  that an action is listed but not yet reflected when that load failed or was
  not done for that reason.
- The document never holds a value of a Runtime environment variable, a role's
  external id, a token, or an account id outside an ARN.

## Status codes of the write endpoints

| Code | Meaning | `detail` |
| --- | --- | --- |
| 200, 201 | Done | (an `ActionResult`) |
| 401 | No bearer token, or one the function does not accept (signature, issuer, audience, kind of token, time). The functions verify the token themselves | `"Not authenticated"` |
| 403 | No mapped group; or the authority, tenant, separation-of-duties or reference rule refused it | The rule's reason, for example `"create requires the registrar role; principal holds 'other' (REG-07-N)"`, `"cross-tenant update is denied"`, `"the submitter cannot approve its own record ... (REG-11-N)"`, `"the registration names a Runtime that runs in a cell of another tenant (REG-13-N)"` |
| 404 | No such registration, or the record is not an agent governance record; also any path or method this function does not serve | `"Registration not found"` or `"Not found"` |
| 409 | The record's status does not permit the action (including every change to a retired record, `RET-03-N`); a record of that name already exists; the update changes nothing; the document changed since it was reviewed; on approve and reject, who submitted the record could not be established (its history holds more than 2000 events since its latest submit) | A sentence to show the user |
| 422 | The body or an id is invalid | A list of field errors, see below |
| 500 | The function is not configured | `"Portal configuration error: ..."` |
| 502 | The registry failed | `"An AWS service call failed (<code>)"` |
| 503 | The audit trail could not be written or read, or the identity provider's signing keys could not be fetched, so nothing was done | A sentence to show the user |

Rule identifiers that can appear in `detail`:

| Identifier | Code | Meaning |
| --- | --- | --- |
| `REG-07-N` to `REG-10-N` | 403 | Create, update, approve or delete without the needed authority |
| `REG-11-N` | 403 | The submitter cannot approve or reject its own record |
| `REG-12-N` | 403 | An approved record's governed references cannot be changed in place |
| `REG-13-N` | 403 | The registration names a Runtime, a Tool Gateway or a policy engine that runs in a cell of another tenant, or in an account that several tenants share while the caller does not hold every one of them (create, update, approve) |
| `RET-01-N` | 403 | Retire without the approver authority |
| `RET-02-N` | 403 | Retire of a record in a tenant the caller does not hold |
| `RET-03-N` | 409 | Approve, reject, update or submit of a retired record |
| `RET-04-N` | 409 | Retire of a record that is still being created or updated |
| `REV-01-N` | 403 | Review without the approver authority |
| `REV-02-N` | 403 | Review of a record in a tenant the caller does not hold |
| `REV-03-N` | 409 | Review of a record that is not `APPROVED` |
| `REV-04-N` | 422 | `next_review_by` is not a date after today and within 366 days |
| `REV-05-N` | 403 | Review by the record's submitter |
| `REV-06-N` | 409 | Review of a record whose review was attested less than 24 hours ago |

`RET-01-P` and `REV-01-P` are the identifiers of the allowing rules. They
appear in the `intent` event of a retire or a review, not in an error.

Notes:

- A caller without the needed authority gets 403 whether or not the record exists.
- 403 and 409 answers carry `request_id`. They are written to the record's
  history when the caller has a part in the record (the authority and the
  record's tenant). Every other refusal is in the function's log under the
  same id and in no history: see `GET /registrations/{record_id}/history`.
- The 503 of a review whose attestation could not be written carries
  `request_id` too: it is recorded as `failed`.
- 401, 404 and 422 are not decisions and are not written to the audit trail.
- A 422 `detail` is always a list of `{ loc, msg, type }`. `loc` starts with
  `"body"` followed by the request's field names, for example
  `["body", "risk_class"]`, `["body", "golden_path", "name"]` or
  `["body", "subscribed_tool_ids"]` (no list position). An error about the
  body as a whole has `loc: ["body"]`; a malformed id has `loc: ["path", "record_id"]`.
  `msg` is a sentence that names the field, for example
  `"risk_class must be one of minimal, limited, high, unacceptable"`.
- On 401 the front end may refresh the token and retry, as for the read API.
  The action functions need the same token the read API gets, in
  `Authorization: Bearer <token>`; they check it themselves and give no
  reason for a refusal.

## Routing

Each function serves only its own routes and answers 404 for anything else:

| Function | Routes |
| --- | --- |
| Read API | every `GET`, including the three above and `GET /agents/{agent_id}/evidence`. Any other method is 405 |
| Registrar | `POST /registrations`, `PUT /registrations/{record_id}`, `POST /registrations/{record_id}/submit`, `DELETE /registrations/{record_id}` |
| Approver | `POST /registrations/{record_id}/approve`, `POST /registrations/{record_id}/reject`, `POST /registrations/{record_id}/retire`, `POST /registrations/{record_id}/review` |

CORS: with `PORTAL_ALLOWED_ORIGINS` set, the registrar function allows `POST`,
`PUT`, `DELETE` and the approver function allows `POST`, with the request
headers `authorization` and `content-type`.
