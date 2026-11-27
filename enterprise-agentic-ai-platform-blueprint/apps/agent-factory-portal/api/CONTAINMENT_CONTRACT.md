# Agent Factory Portal: containment contract

Containing an agent blocks every invocation of its Runtime and stops its
running sessions. Releasing it lifts the block. Both are governed actions with
an audit trail, served by a function of their own.

All paths are under `/api/v1`. Requests carry `Authorization: Bearer <token>`.
`{id}` is the agent's `id` as returned by `GET /agents`.

## Who may do what

| Action | Portal role (`portal_role` on `/users/me`) | Also required |
| --- | --- | --- |
| contain | `security`, `platform` or `sre` | The caller holds the agent's tenant |
| release | `security` or `platform` | The caller holds the agent's tenant, and is **not** the person who contained the agent |

- **Two-person rule.** The person who contained an agent cannot release it.
  The `platform` role does not bypass this. Show Release as unavailable when
  `contained_by_me` is true.
- **Tenant.** `platform` holds every tenant. Others hold the tenants of their
  groups. An agent with no known tenant can be acted on only by `platform`
  and `security`.
- **Tenant of an agent that has no registration.** It is the tenant of the
  cell account its Runtime runs in when every configured cell there has the
  same tenant, and unknown otherwise.
- `GET /users/me` returns `can_contain` and `can_release` (booleans, from the
  caller's role). `can_release` does not account for the two-person rule: use
  `contained_by_me` on the containment view for that. The function enforces
  all of it either way.

## What contain does

In the agent's cell, with that cell's containment role:

1. Reads the Runtime's resource policy.
2. Adds one statement, with Sid `AgenticAIPortalContainment`, that denies
   every invoke action on the Runtime to every principal. Every other
   statement in the policy is kept exactly as it was.
3. Reads the policy back to verify the statement is there.
4. Finds the Runtime's sessions of the last eight hours and stops each one,
   at most 200 and within a time limit. No API lists a Runtime's sessions, so
   they are found in two places: the Runtime's traces (an instrumented agent)
   and the names of its session log streams (any agent that writes output).
   `sessions.sources` says how many each gave, for example "found 3 sessions
   (2 in traces, 3 in logs)". It is informational.

**Enforcement is not instant, and the two directions differ.** The service
applies a policy change host by host (measured on a live Runtime under steady
calls):

- After contain, an occasional invocation still succeeded for up to 52
  seconds, and none after that. Allow 90 seconds.
- After release, a large share of calls was still refused for the first
  minutes; the last refusal came 263 and 269 seconds later in two runs, and
  none in the seven minutes that followed. Allow five minutes.

`state` changes as soon as the statement is verified. Each result carries
`enforcement_delay_seconds` for the action it reports (90 for contain, 300 for
release), and the view carries both (`enforcement_delay_seconds` for contain,
`release_delay_seconds` for release). Tell the user "Contained. Invocations
are blocked within about 90 seconds." and "Released. Some calls can still be
refused for about 5 minutes." rather than "now".

Release removes exactly that statement and verifies. If the policy held
nothing else, the policy is deleted. Release does not restart anything.

Both actions are idempotent: containing a contained agent, or releasing one
that is not contained, changes nothing and answers `outcome: "unchanged"`.

If containment is not enabled for the agent's cell (the cell has no
containment role), both actions answer 409.

## Types

```ts
interface ContainmentInput {
  reason: string;          // required, 1 to 1000 characters
  runtime_arn?: string;    // only for an agent that has no registration, see below
}

interface ContainmentResult {
  action: "contain" | "release";
  outcome: "allowed" | "unchanged";   // unchanged: it was already in the requested state
  reason: string;                     // the caller's reason followed by what was done
  request_id: string;                 // ties the response to its audit events
  agent_id: string;
  runtime_arn: string;
  state: "contained" | "not_contained";   // verified by reading the policy back
  changed: boolean;
  policy_deleted: boolean;            // release only: the policy held nothing else and was deleted
  other_statements_kept: number;      // statements in the policy that are not the portal's
  sessions: SessionsStopped | null;   // contain only
  steps: ContainmentStep[];           // what was done, in order
  partial: boolean;                   // true: contained, but the session step did not fully complete
  denied_actions: string[];           // contain: the invoke actions the statement denies
  enforcement_delay_seconds: number;  // how long this change can take to apply everywhere: 90 for contain, 300 for release
  audit_complete: boolean;            // false: done, but its result event could not be written
}

interface ContainmentStep {
  id: "policy" | "verify" | "sessions";
  label: string;                      // a sentence fragment to show, for example "Stop the Runtime's running sessions"
  status: "done" | "unchanged" | "partial" | "failed" | "skipped";
  detail: string | null;              // a sentence saying what happened
}

interface SessionsStopped {
  // "ok": both sources were read. "ok; <what was incomplete>": one source could not be read, or only the
  // DEFAULT endpoint could be checked. "sessions could not be listed (<why>)": neither source could be read.
  discovery: string;
  sources: { spans: number; log_streams: number };  // where sessions were found, before de-duplication
  found: number;       // distinct sessions, after merging the two sources
  stopped: number;
  not_active: number;  // unknown or already ended: no stop was needed
  failed: number;      // could not be stopped
  not_attempted: number;  // the time limit ran out first
  stop_errors: string[];  // error codes of the stops that failed
}

interface ContainmentView {
  agent_id: string;
  state: "contained" | "not_contained" | "unknown";
  runtime_arn: string | null;
  enabled: boolean;                   // containment is enabled for the agent's cell
  contained_by: string | null;        // subject id, equal to `oid` on /users/me
  contained_by_label: string | null;
  contained_at: string | null;        // ISO 8601 UTC
  reason: string | null;
  contained_by_me: boolean;           // the caller contained it and so cannot release it
  detail: string | null;              // why the state is unknown, as a sentence to show
  partial: boolean;                   // the containment that holds did not stop every session it found
  enforcement_delay_seconds: number;  // 90: how long a contain can take to apply everywhere
  release_delay_seconds: number;      // 300: how long a release can take to apply everywhere
  events: AuditEvent[];               // newest first; the AuditEvent of ACTIONS_CONTRACT.md
}
```

Containment events use the `AuditEvent` shape of ACTIONS_CONTRACT.md with
`action` `contain` or `release`, and these extra fields: `agent_id`,
`runtime_arn`, `sessions_found`, `sessions_stopped`, `sessions_failed` and
`detail` (`ok`, or why sessions could not be listed or stopped).
`status_before` and `status_after` are `contained`, `not_contained` or
`unknown`. `outcome` can be `allowed`, `unchanged`, `denied` or `failed`.

## Read endpoint (read API, any mapped role)

### `GET /agents/{id}/containment`

Returns `ContainmentView`. `state` is read fresh from the Runtime's resource
policy, so it is correct immediately after an action (the `flags.contained`
field on `GET /agents` can lag by the cache lifetime, 30 seconds by default).
`state` is `unknown` when the policy cannot be read or the agent's account has
no reader (the normal case for an agent the organization registry detected in
an account that is not a cell); `detail` then says which, for example "There
is no reader in this agent's account, so its containment state cannot be
read." `enabled` is false for such an agent, so offer no action. `contained_by`, `contained_at` and `reason` are set while the
agent is contained through the portal; a Runtime contained by other means
shows `contained` with those fields null.

Status codes: 200; 401; 403 (no mapped group); 404 (no such agent); 422 (malformed id).

## Action endpoints (containment function)

### `POST /agents/{id}/containment/contain` and `POST /agents/{id}/containment/release`

Body: `ContainmentInput`. Returns 200 with `ContainmentResult`.

`runtime_arn` is needed only when the agent has no registration (its `id` is
its Runtime id) **and** more than one cell account has containment enabled.
Send the agent's `agent_arn` in that case; sending it always for an
unregistered agent is fine. It must be the ARN of that same Runtime. For a
registered agent the Runtime is read from its registration and `runtime_arn`
is not needed.

| Code | Meaning | `detail` |
| --- | --- | --- |
| 200 | Done, or already in that state | (a `ContainmentResult`) |
| 401 | Missing or unusable token | `"Not authenticated"` |
| 403 | No mapped group; or the role, tenant or two-person rule refused it | The rule's reason, for example `"contain requires the security, platform or sre role; principal holds 'developer' (CON-01-N)"` or `"the person who contained the agent cannot release it - two-person rule (CON-03-N)"` |
| 404 | No such agent; also any path or method this function does not serve | `"Agent not found"` or `"Not found"` |
| 409 | Containment is not enabled for the agent's cell; the registration names no Runtime; the existing policy cannot be parsed | A sentence to show the user |
| 422 | The body or the id is invalid, or `runtime_arn` is missing or wrong | A list of `{ loc, msg, type }` |
| 500 | The function is not configured | `"Portal configuration error: ..."` |
| 502 | An AWS call failed part-way | A sentence that says what was and was not done, for example `"The deny statement could not be written (AccessDeniedException). Nothing was changed."`. The body also has `steps` (the same `ContainmentStep` list), `action` and `request_id` |
| 503 | The audit trail could not be written or read, so nothing was done | A sentence to show the user |

Notes for the UI:

- **A 200 can still carry bad news about sessions.** Containment succeeds as
  soon as the deny statement is verified. `partial` is true when the session
  step was not clean: a source of session ids could not be read, some sessions
  could not be stopped, or the time limit ran out. The `sessions` step then
  has status `partial` (or `failed` when no source could be read) with a
  sentence in `detail`, and `sessions` has the counts. Show the steps. The
  agent is contained regardless: the deny statement blocks further
  invocations, including on sessions that are still running.
- **Finding no session is normal.** An agent that emits no traces and writes
  no output has nothing to find; `found` is 0 and the step is `done`.
- **There are no intermediate states.** The actions are synchronous; `state`
  is never "containing" or "releasing". A request can take up to about 25
  seconds when many sessions are stopped.
- **A 502 always says what state the agent is in.** After a 502, re-read
  `GET /agents/{id}/containment` and show its `state`.
- 403, 409 and 502 answers carry `request_id` and are in the audit trail.
- After a successful action, refresh `GET /agents/{id}/containment`.
- A caller without the role gets 403 whether or not the agent exists.

Rule identifiers in `detail`: `CON-01-N` (role for contain), `CON-02-N` (role
for release), `CON-03-N` (two-person rule), `CON-04-N` (tenant not held),
`CON-05-N` (agent with no known tenant).

## Routing

The containment function serves only the two `POST` routes above and answers
404 for anything else. The read API serves the `GET` and answers 405 for the
two `POST` routes. The registrar and approver functions answer 404 for all
three.

CORS: with `PORTAL_ALLOWED_ORIGINS` set, the containment function allows
`POST` with the request headers `authorization` and `content-type`.
