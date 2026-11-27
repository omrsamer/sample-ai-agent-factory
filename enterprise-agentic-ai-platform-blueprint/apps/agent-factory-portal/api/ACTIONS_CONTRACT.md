# Agent Factory Portal: registration and approval contract

Endpoints for registering agent records in the platform AWS Agent Registry and
deciding on them. Three read endpoints are part of the read API; six write
endpoints are served by two separate functions, each with its own IAM role.

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

Rules the functions enforce (the reason text is returned in `detail`):

- Create, update, submit and delete need the registrar authority and a tenant the caller holds.
- Approve and reject need the approver authority and a tenant the caller holds.
- The person who submitted a record cannot approve or reject it, even with the
  `platform` role (`REG-11-N`). The submitter is whoever last submitted it through the portal.
- On an APPROVED record, an update that changes `runtime_arn`, `gateway_arn`,
  `subscribed_tool_ids`, `risk_class` or `data_classification` is refused
  (`REG-12-N`, with a `hint`). Register a new record instead.

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

Two consequences to show in the UI:

- **Any update returns the record to `DRAFT`**, including an update of an
  approved or pending record. It must be submitted and approved again. Warn
  before saving a change to an approved record.
- **A rejected record cannot be submitted again as it is.** Update it first
  (which makes it `DRAFT`), then submit.

`CREATING` and `UPDATING` last about a second. The write endpoints wait for
them to pass before answering, so a response normally shows a settled status.

## Types

```ts
interface Registration {
  record_id: string;               // 12 letters and digits
  name: string;                    // "agent-<tenant_id>-<agent_id>-<environment>"
  status: string;                  // registry status, see above
  status_reason: string | null;    // the approver's reason, cut to 255 characters by the registry
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
  action: "create" | "update" | "submit" | "delete" | "approve" | "reject";
  outcome: "allowed";
  reason: string;                  // why it was allowed; for approve and reject, the approver's reason
  request_id: string;              // ties the response to its audit events
  registration: Registration | null;  // null after a delete
  audit_complete: boolean;         // false: the action was done but its result event could not be written
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
}

interface AuditEvent {
  event_id: string;
  request_id: string;              // the intent and result of one action share it
  at: string;                      // ISO 8601 UTC, microseconds
  phase: "intent" | "result";
  action: "create" | "update" | "submit" | "delete" | "approve" | "reject";
  outcome: "allowed" | "denied" | "failed";
  reason: string;
  actor_subject: string;
  actor_label: string;             // name, else email, else user name, else the subject
  actor_role: string;              // portal role at the time
  tenant_id: string | null;
  record_id: string | null;        // null for a create that had no record yet
  record_name: string | null;
  document_sha256: string | null;
  status_before: string | null;
  status_after: string | null;     // "DELETED" after a delete
}

interface RegistrationHistory {
  record_id: string;
  events: AuditEvent[];            // newest first
}

interface ErrorBody {
  detail: string | { loc: string[]; msg: string; type: string }[];
  action?: string;                 // present on 403 and 409 from an action
  request_id?: string;             // present when the refusal was written to the audit trail
  hint?: string;                   // present on REG-12-N
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

`previous_approved` is the document as it was at the latest approval made
through the portal, for showing an approver what changed. The registry keeps
only the current document, so the portal stores the approved document with the
approval's audit event. It is null when the record was never approved through
the portal, including records approved before this was introduced or approved
outside the portal. While the record is `APPROVED` and unchanged it equals `document`.

Status codes: 200; 401; 403; 404 (no such record, or not an agent governance
record); 422 (malformed id); 502.

### `GET /registrations/{record_id}/history`

Returns `RegistrationHistory`. Works for a deleted record. Every decision is
there, allowed or denied. An allowed action appears as two events with the same
`request_id`: an `intent` written before the action and a `result` written
after it (`allowed`, or `failed` if the registry refused). A denied action is
one `result` event with `outcome: "denied"`. Refused creations of a record with
the same name are included.

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

## Status codes of the write endpoints

| Code | Meaning | `detail` |
| --- | --- | --- |
| 200, 201 | Done | (an `ActionResult`) |
| 401 | Missing or unusable token | `"Not authenticated"` |
| 403 | No mapped group; or the authority, tenant or separation-of-duties rule refused it | The rule's reason, for example `"create requires the registrar role; principal holds 'other' (REG-07-N)"`, `"cross-tenant update is denied"`, `"the submitter cannot approve its own record ... (REG-11-N)"` |
| 404 | No such registration, or the record is not an agent governance record; also any path or method this function does not serve | `"Registration not found"` or `"Not found"` |
| 409 | The record's status does not permit the action; a record of that name already exists; the update changes nothing; the document changed since it was reviewed | A sentence to show the user |
| 422 | The body or an id is invalid | A list of field errors, see below |
| 500 | The function is not configured | `"Portal configuration error: ..."` |
| 502 | The registry failed | `"An AWS service call failed (<code>)"` |
| 503 | The audit trail could not be written or read, so nothing was done | A sentence to show the user |

Notes:

- A caller without the needed authority gets 403 whether or not the record exists.
- 403 and 409 answers are written to the audit trail and carry `request_id`.
- 401, 404 and 422 are not decisions and are not written to the audit trail.
- A 422 `detail` is always a list of `{ loc, msg, type }`. `loc` starts with
  `"body"` followed by the request's field names, for example
  `["body", "risk_class"]`, `["body", "golden_path", "name"]` or
  `["body", "subscribed_tool_ids"]` (no list position). An error about the
  body as a whole has `loc: ["body"]`; a malformed id has `loc: ["path", "record_id"]`.
  `msg` is a sentence that names the field, for example
  `"risk_class must be one of minimal, limited, high, unacceptable"`.
- On 401 the front end may refresh the token and retry, as for the read API.

## Routing

Each function serves only its own routes and answers 404 for anything else:

| Function | Routes |
| --- | --- |
| Read API | every `GET`, including the three above. Any other method is 405 |
| Registrar | `POST /registrations`, `PUT /registrations/{record_id}`, `POST /registrations/{record_id}/submit`, `DELETE /registrations/{record_id}` |
| Approver | `POST /registrations/{record_id}/approve`, `POST /registrations/{record_id}/reject` |

CORS: with `PORTAL_ALLOWED_ORIGINS` set, the registrar function allows `POST`,
`PUT`, `DELETE` and the approver function allows `POST`, with the request
headers `authorization` and `content-type`.
