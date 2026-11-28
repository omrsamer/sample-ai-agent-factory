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
| release | `security` or `platform` | The caller holds the agent's tenant, the tenant is still the one the agent was contained under, and the caller is **not** the person who contained the agent |

- **Two-person rule.** The person who contained an agent cannot release it.
  The `platform` role does not bypass this. Show Release as unavailable when
  `contained_by_me` is true.
- **Tenant.** `platform` holds every tenant. Others hold the tenants of their
  groups. An agent whose tenant cannot be determined can be acted on only by
  `platform`.
- **Which tenant decides.** The tenant of the place the Runtime runs in. A
  registration plays no part, approved or not: it is written by the people it
  governs. When every cell configured for the Runtime's account and Region
  has the same tenant, that is the tenant, for a registered and an
  unregistered agent alike. In an account shared by several tenants it is the
  value of the Runtime's own `tenant-id` tag, which the cell's pipeline sets,
  when that names one of those tenants. A Runtime there with no such tag,
  with a tag that names a tenant the account does not host, or whose tag
  cannot be read has no determined tenant, and only `platform` can act on it
  (`CON-05-N`). So a registration that names another tenant's Runtime gives
  nobody any authority over that Runtime.
- **A tenant that changed.** A release needs the Runtime's tenant to be the
  one it was contained under (`CON-06-N`). In a shared account the tenant
  comes from the Runtime's tag, and whoever can change that tag could
  otherwise move a contained Runtime into their own tenant and release it
  there. A Runtime whose tenant changed since it was contained, or was not
  known then, can be released by `platform` only. The contain event records
  the tenant.
- **One history per Runtime.** The two-person rule and the history follow
  the Runtime, whatever id a request used (a registration's id, or the
  Runtime's own id). A person who contained an agent under one id cannot
  release it under another.
- **One ARN per Runtime.** The service answers for more than one spelling of
  a Runtime's ARN: another partition string reads the same resource policy.
  The portal uses one. It builds the ARN itself, from the partition, Region
  and account of the Runtime's cell as the operator configured them and the
  Runtime id as given, and uses that ARN for every call in the cell and for
  the history. A `runtime_arn` in a request must be equal to it, character
  for character; anything else is refused with 422 before anything is read.
  A registration that spells its Runtime's ARN another way is not acted on
  (409).
- **Who writes into a Runtime's history.** Only a caller who has a part in
  the Runtime: the role for the action, and the Runtime's tenant. A refusal
  of anyone else is in the function's log with its `request_id`, not in the
  history (see "Notes for the UI").
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
   most recent first, at most 1000 per action and within a time limit. When a
   limit cuts the list, `sessions.discovery` says that more sessions may be
   running and the result is `partial`; containing again continues, because a
   session that was already stopped needs no second stop. No API lists a
   Runtime's sessions, so they are found in the names of its session log
   streams (any agent that writes output; no log event is read). A cell can
   opt in to a second source, the Runtime's traces, which finds a session of
   an instrumented agent that wrote no output. `sessions.sources` says how
   many each source gave. It is informational, and it names only the sources
   that were asked: without the opt-in there is no `spans` entry.
5. When the portal is deployed with a sweep queue, leaves the background
   sweeps of this containment on that queue (see "Background sweeps"). The
   request does not wait for them. Without a queue this step does not exist
   and everything else is the same.

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

**Contained means the portal's statement, whole.** A Runtime is contained
when its policy holds the statement the portal writes, and that statement is
recognised by all of it, not by its Sid: `Effect` `Deny`, `Principal` `"*"`,
`Resource` the Runtime's ARN, `Action` a list that holds the two core invoke
actions and nothing but invoke actions, and no other element (no `Condition`,
`NotAction`, `NotPrincipal` or `NotResource`). Whoever can write the
Runtime's policy can put a statement under the portal's Sid that denies
nothing: an `Allow`, a condition that never holds, one harmless action. A
statement in another shape can also deny invocation, to some callers or to
all: another form of the principal, action names in another case. The portal
does not try to tell which. A statement under its Sid that is not the one it
writes is not containment by the portal, wherever the portal looks:

- The view and `flags.contained` say `not_contained`, and the view's `detail`
  says: "A statement with the portal's identifier is in the Runtime's resource policy, but it is not the statement the portal writes and may or may not deny invocation; contain the agent to replace it."
  The sentence claims nothing about what that statement does.
- A contain replaces it with the portal's statement, stops the sessions as
  for any contain, and says so: `replaced_foreign_statement` is true and the
  `reason`, the `policy` step and the result event carry the sentence "A
  statement with the portal's identifier that the portal had not written was
  in the policy and was replaced."
- A release leaves it where it is, answers `unchanged`, and says that the
  statement the portal writes was not there to remove, with the same sentence.
- A sweep stops nothing (outcome `skipped`), and says the same.

Both actions are idempotent: containing a contained agent, or releasing one
that is not contained, changes nothing and answers `outcome: "unchanged"`.

**A contain repeated while its sweeps are at work does nothing.** A contain
of an agent that is already contained stops the sessions it finds and
schedules sweeps again, but only once the sweeps of the last contain are
over: no sooner than 15 minutes after the last contain that scheduled
sweeps, and not while one of those sweeps has yet to report (a sweep that has
not reported 30 minutes after its contain is given up). Until then it
answers at once:

- `outcome` is `unchanged` and `retry_after_seconds` says in how many seconds
  to ask again. In every other answer that field is null. While a sweep has
  yet to report it is the earliest that a contain can do its work again: the
  rest of the 15 minutes, and after those, 60 seconds for as long as a sweep
  that is due has not reported.
- `sessions` is null and `sweeps_scheduled_in_seconds` is empty. The steps
  are `policy` (`unchanged`), `verify` (`done`) and `sessions` (`skipped`),
  whose `detail` says "The background sweeps of this containment are still
  running, so nothing more was done. A contain stops sessions again once they
  have run: ask again in about N minutes."
- No session is listed or stopped and nothing is scheduled.
- The history gets one `result` event for it (`contain`, `unchanged`, with
  no intent before it and no session counts), once for each person who asks
  again during that time. A person who asks again and again leaves that one
  event; the later answers are in the function's log under their
  `request_id`.
- Whatever the earlier request left undone, its sweeps do. The view's
  `sweeps` and `quiet_at` show how far they are.

The policy has the last word: if the portal's statement is not there any
more, the contain does its work at once. And a contain that scheduled no
sweep (the portal runs without a sweep queue, or the queue could not be
reached) is never too soon to repeat, because containing again is then the
only way to stop the sessions that are left.

If containment is not enabled for the agent's cell (the cell has no
containment role), both actions answer 409.

## Background sweeps

A contain request has seconds. Two things outlast it: an agent can have more
sessions than one request can list and stop, and for up to 90 seconds after
the statement is written a host that has not applied it yet can still start a
session. So a contain also schedules up to three sweeps, which a separate
function (the sweeper) runs later with no caller waiting:

| Sweep | Runs | Why |
| --- | --- | --- |
| 1 | At once | Only when the request left something undone: a session it could not stop, a list that a limit cut, a source it could not read. When the request dealt with every session it found, this sweep is not scheduled and the `background` step says "No background sweep is needed now." |
| 2 | 120 seconds after the contain | After every host applies the deny (90 seconds), so it catches the sessions that started in between |
| 3 | 900 seconds after the contain | A last pass. 900 seconds is the longest delay the queue allows |

Each sweep, on its own:

1. Reads the Runtime's containment history (both of its ranges, see "The
   Runtime's history"), back to the contain whose request
   id the message carries. A message proves nothing: whoever can invoke the
   sweeper writes any request id and any sweep number into one. The sweep is
   run only when the history says all of this:
   - a contain with that request id is on record and scheduled sweeps;
   - this sweep is one of them. The contain's result lists the sweeps it
     scheduled (`sweeps_scheduled_numbers`, for example `"2,3"`), and the
     sweeper admits only the sweeps that the contain's result lists. A first
     sweep for a contain that needed none would otherwise run at once and
     count as one of its sweeps. A first sweep can reach the sweeper before
     its contain has written that result, so the sweeper waits for that
     result for up to 40 seconds, counted from the contain's intent, which
     is longer than the containment function can run. A result that has not
     come by then was lost: the second and third sweep, which every contain
     schedules, are still admitted; a first sweep is not;
   - this sweep has not left its event yet;
   - it is due. A sweep is run no earlier than 30 seconds before it is due,
     counted from the contain's own events. The queue never delivers a
     message early, so one that is early was not sent by the contain, and
     running it would use up a late sweep before the sessions it is there
     to catch can have started;
   - no later containment has taken that contain's place. A sweep whose
     contain belongs to an earlier containment, which was released, is not
     run once the Runtime is contained again: the sweeps of the contain that
     holds do the work.

   It then claims the sweep with one conditional write, so that a second
   delivery of the message, a replay or a second invocation at the same
   moment cannot run it as well. A message that fails any of this is not
   run and leaves no event: it goes to the function's log. One that came
   before its sweep is due is also handed back to the queue (the invocation
   fails), so that nothing is lost if it did come from there; the sweep is
   not used up, and the real message runs it when it is due.
2. Reads the Runtime's resource policy. **If the portal's statement is gone,
   it stops nothing** (outcome `skipped`). A release cancels no sweep; this
   check is what makes a sweep that arrives after a release harmless. It
   stops nothing either when the statement is still there but the history
   says that the Runtime was released after this sweep's contain (a release
   that is under way; outcome `skipped`), or when the policy cannot be read
   (outcome `failed`).
3. Lists the Runtime's sessions of the last eight hours with no limit on
   their number: every page of session log stream names, and in a cell that
   opted in to traces, up to 10,000 sessions from that source as well.
4. Stops them, most recent first, at no more than 20 stops per second. While
   it does, it reads the policy again every 30 seconds, and if the agent was
   released meanwhile the sweep ends there (outcome `skipped`, with the
   counts of what it had stopped until then).
5. Writes one event in the Runtime's history: action `sweep`, with what it
   found, what it stopped and how long it took.

**What a sweep writes, and how often.** A history is never shortened. So the
sweeper writes into a
history only for a sweep that a contain on record scheduled, and once: one
event for each sweep that the contain scheduled, so two or three for one
contain, whoever sends or replays messages or invokes the function. A sweep
changes nothing about who holds a containment, so its event is written into
the range of the history that a release does not read. The
event carries the agent id of the contain, taken from the contain's own
events, and nothing of the message but the request id and the sweep number
that the history confirmed. Beside the event the sweeper writes one item that
is not an event, the claim of step 1: sort key
`SWEEP#<request id>#<sweep number>`, in the Runtime's own partition. No read
of a history returns a claim, and like every item of the table it is never
changed or deleted.

**One invocation, one sweep.** The sweeper runs exactly one message for each
invocation. The queue hands it one at a time. An invocation with no record,
or with more than one, did not come from the queue as it is set up: it is
logged and nothing in it is run. Several records would share one
invocation's time, and a long sweep of one Runtime put first would leave a
due sweep of another none.

A sweep that was claimed and has left no event is still running, or its run
was cut short. Either way it is not run a second time. A further delivery of
its message fails, so the message comes back: if the event has appeared by
then, the message is done with; if it never does, the message ends in the
dead-letter queue, where an alarm says so. Contain the agent again to
schedule new sweeps.

A sweep's outcome is `allowed` only when it read every source to its end and
left no session unstopped. Anything less is `failed`, and its `reason` says
what was left: sessions that could not be stopped, sessions not attempted
before the function's time ran out, or a source that was not read to its
end. What it did stop stays stopped.

**When is the agent quiet?** `quiet_at` on the containment view is the time
at which the first sweep ended that started at least 90 seconds after the
containment began and had outcome `allowed`. From then on, every session the
portal could find has ended or was stopped, and the deny statement keeps new
ones from starting. It is null until such a sweep has run, and null again
after a release. It says nothing about a session that left no trace in the
sources the portal reads (an agent that writes no output, in a cell without
the traces option).

Limits, so that nothing here reads as more than it is:

- A sweep lasts at most one invocation of its function (15 minutes). At 20
  stops per second that is about 17,000 sessions. Each sweep starts over,
  most recent first, so three sweeps do not reach further than one. A Runtime
  with more sessions than that in eight hours needs a higher rate (one
  constant, `SWEEP_STOPS_PER_SECOND`).
- No API says which sessions are live, so a sweep calls stop for every
  session of the last eight hours, ended or not. `sessions_found` on a sweep
  event is therefore the number of sessions of that window, not the number
  that were running; `sessions_stopped` is the number that were.
- A sweep that fails is not repeated, and one whose run was cut short before
  it wrote its event is not run again. Sweeps 2 and 3 run however sweep 1
  ended. If the last one fails, `quiet_at` stays null; contain the agent
  again to schedule more.
- A sweep whose message arrives so late that more than 2000 events were
  recorded since its contain is not run: what a sweep reads of the history
  then no longer says whether it has run.
- If the sweeps cannot be scheduled, the contain still succeeds: the
  `background` step is `failed`, `partial` is true, and the step's `detail`
  says how many were scheduled. Contain again to schedule them. The same
  holds when the function's queue setting is wrong: the step's `detail` then
  names the setting, and a release is not affected at all.
- Without a sweep queue there are no sweeps: no `background` step,
  `sweeps_scheduled_in_seconds` is empty, and the view shows
  `sweeps.scheduled` 0 and `quiet_at` null.

## The Runtime's history

Every contain, release, refusal and sweep leaves events in the Runtime's
history, which is one partition of the audit table:
`CONTAINMENT#<Runtime ARN>`. Every event is written once, into one of two
ranges of that partition:

| Sort key begins with | Holds | Read by |
| --- | --- | --- |
| `EVENT#` | The events that can change who holds the containment: the intent and the result of a contain that writes the statement, of a release that removes it, and of the first contain that finds the statement in place with nobody on record as holding it | A release, to find who contained the Runtime. Also the view, the sweeper and the check before a contain |
| `OTHER#` | Every other event: a background sweep, a refusal, a contain of a Runtime that is already contained and held (it stops sessions and schedules sweeps, and changes nothing about who holds it), a contain that was answered at once, a release of a Runtime that is not contained, and an attempt that could not read the Runtime's policy | The view, the sweeper and the check before a contain. Never a release |

- **A release finds who holds a containment whatever number of sweeps and
  repeated contains were recorded since.** It reads the first range only,
  back to the event that settles the holder. One settled contain is followed
  there by nothing until the next contain or release that changes something.
  Before, every event was in the one range: a contain repeated every sixteen
  minutes (an intent, a result and two or three sweeps each time) put the
  contain that holds the Runtime out of a release's reach after five and a
  half days, with no misuse needed, only an automation during a long
  incident.
- **Which range an event goes into follows from what the request can
  change**, never from anything the caller sends. The containment function
  reads the Runtime's policy before it writes the intent; reading changes
  nothing, and that read is the one the action then works with. A contain
  that will write the statement and a release that will remove it are
  written into the first range, intent and result both. So is a contain that
  finds the statement in place while the history says that nobody holds the
  containment (the Runtime was contained by other means): the first person
  to assert a containment holds it, and a release must find that person.
  Every other request is written into the second range, intent and result
  both.
- **An attempt that could not read the policy leaves one event:** a `result`
  with outcome `failed`, in the second range, with no intent before it.
  Nothing was about to be changed. This covers a containment role that
  could not be assumed, a policy that could not be read, and one that could
  not be parsed. Before, such an attempt left an intent and a result.
- **What is left of the bound.** A release reads at most 2000 events of the
  first range. What can still pile up there without settling anything is a
  request that was about to change the policy and failed at that write (the
  service refused it): an intent and a result, two events for each such
  failure, and no caller brings one about at will. A thousand of them in a
  row, with no contain or release in between that worked, would again put
  the holder out of reach. The release then answers 409 with "The Runtime's containment history holds more than 2000 events since its last contain or release, so who contained it could not be established. The Runtime was not released."
  and the view's `detail` says "Who contained the agent could not be established: the Runtime's history holds more than 2000 events since its last contain or release."
  The remedy is the one it was: remove the statement in the cell account,
  then contain and release through the portal.
- **A history written before there were two ranges** holds everything in
  the first. Nothing is moved, and it is read the same way. For a
  containment that began before the upgrade, the sweeps and repeated
  contains recorded until then still count towards the bound; they stop
  growing with it, because new ones are written into the second range.
- **Refusals.** A refused release (`CON-03-N`, `CON-06-N`) is written once
  for each person, rule and containment, into the second range, and logged
  after that. A mark in the Runtime's partition (`ONCE#<hash>`, written with
  the condition that it does not exist) makes the "once" hold without a
  read of the history. If the mark cannot be written, the refusal is logged
  and not recorded.

Nothing in a response changes shape for this. Two things show in `events`:
an attempt that could not read the policy is one event where it was two, and
the list is the newest 200 events of the two ranges together, in the order
they were written.

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
  replaced_foreign_statement: boolean;   // contain only: a statement with the portal's Sid that the portal had not written was in the policy and was replaced
  policy_deleted: boolean;            // release only: the policy held nothing else and was deleted
  other_statements_kept: number;      // statements in the policy that are not the portal's
  sessions: SessionsStopped | null;   // contain only
  steps: ContainmentStep[];           // what was done, in order
  partial: boolean;                   // true: contained, but the session step did not fully complete, or the background sweeps could not be scheduled
  denied_actions: string[];           // contain: the invoke actions the statement denies
  enforcement_delay_seconds: number;  // how long this change can take to apply everywhere: 90 for contain, 300 for release
  sweeps_scheduled_in_seconds: number[];  // contain: the delay of each background sweep it scheduled, for example [120, 900]. Empty on a release and without a sweep queue
  retry_after_seconds: number | null;     // contain with outcome "unchanged": set when the request did nothing because the sweeps of the last contain are still at work; in how many seconds to ask again. Null otherwise
  audit_complete: boolean;            // false: done, but its result event could not be written
}

interface ContainmentStep {
  id: "policy" | "verify" | "sessions" | "background";   // "background": contain only, and only with a sweep queue
  label: string;                      // a sentence fragment to show, for example "Stop the Runtime's running sessions"
  status: "done" | "unchanged" | "partial" | "failed" | "skipped" | "scheduled";   // "scheduled": the background step
  detail: string | null;              // a sentence saying what happened
}

interface SessionsStopped {
  // "ok": every source that was asked was read. "ok; <what was incomplete>": a source could not be read, a
  // limit cut the list, or only the DEFAULT endpoint could be checked. "sessions could not be listed
  // (<why>)": no source could be read.
  discovery: string;
  // Where sessions were found, before de-duplication. `spans` is present only when the cell opted in to it.
  sources: { log_streams: number; spans?: number };
  found: number;       // distinct sessions, after merging the sources
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
  contained_by_label: string | null;  // a label to read beside that subject: a verified or directory-set email or user name, else the subject id. It can change for the same person; the two-person rule compares subjects. Never a display name
  contained_at: string | null;        // ISO 8601 UTC
  reason: string | null;
  contained_by_me: boolean;           // the caller contained it and so cannot release it
  detail: string | null;              // a sentence to show: why the state is unknown; or, with state not_contained, that a statement with the portal's Sid is in the policy that is not the one the portal writes (it may or may not deny invocation); or, with state contained, that who contained the agent could not be established
  partial: boolean;                   // the containment that holds did not stop every session it found
  enforcement_delay_seconds: number;  // 90: how long a contain can take to apply everywhere
  release_delay_seconds: number;      // 300: how long a release can take to apply everywhere
  sweeps: { scheduled: number; done: number };   // background sweeps of the containment that holds: how many it scheduled, and how many of those have run
  quiet_at: string | null;            // ISO 8601 UTC: since when no session the portal can find is running; see "Background sweeps"
  events: AuditEvent[];               // the newest 200 events of the Runtime's history, newest first; the AuditEvent of ACTIONS_CONTRACT.md
  events_truncated: boolean;          // true: the history holds older events that are not listed
}
```

Containment events use the `AuditEvent` shape of ACTIONS_CONTRACT.md with
`action` `contain`, `release` or `sweep`, and these extra fields: `agent_id`,
`runtime_arn`, `sessions_found`, `sessions_stopped`, `sessions_failed` and
`detail` (`ok`, or why sessions could not be listed or stopped).
`status_before` and `status_after` are `contained`, `not_contained` or
`unknown`. `outcome` can be `allowed`, `unchanged`, `denied` or `failed`.
The result event of a contain that scheduled background sweeps also has
`sweeps_scheduled` (how many) and `sweeps_scheduled_numbers` (which, as text:
`"2,3"` when the request dealt with every session it found, `"1,2,3"` when it
left something undone, fewer when not every message could be sent).

A `sweep` event is written by the sweeper, one per sweep, with no intent
event before it:

| Field | Value |
| --- | --- |
| `action`, `phase` | `sweep`, `result` |
| `outcome` | `allowed` (every source read to its end, nothing left unstopped), `failed` (see `reason`) or `skipped` (the Runtime was no longer contained, or its history says that it was released after the sweep's contain: nothing was stopped, or nothing more when the release came while the sweep ran) |
| `request_id` | The request id of the contain that scheduled it |
| `sweep` | 1, 2 or 3 |
| `actor_subject`, `actor_label`, `actor_role` | `agent-factory-portal`, `Agent Factory Portal (background sweep)`, `system`. A sweep is nobody's contain or release: it never changes who holds the containment, and the two-person rule ignores it |
| `sessions_found`, `sessions_stopped` | As for a contain. Null when the sweep ended before it listed any session (`skipped`, or a policy or a session list that could not be read) |
| `sessions_not_active` | Sessions that had already ended, so needed no stop |
| `sessions_failed` | Sessions that could not be stopped, plus those not attempted before the function's time ran out. Sessions left alone because the agent was released are not counted here |
| `duration_ms` | How long the sweep took, from reading the message to writing this event |
| `detail` | `ok`, or what kept the list from being whole |
| `status_before`, `status_after` | The state the sweep saw when it began and when it ended: `contained`, `not_contained` or `unknown`. They differ only when the agent was released while the sweep ran |
| `tenant_id` | The tenant of the Runtime's cell, when its account and Region have one tenant |

A message that is not valid leaves no event. It is never run, never retried
and only logged, also when it names a Runtime of a cell with containment
enabled by the ARN the portal builds for that cell. The same holds for a
message that is valid in every other respect but spells the Runtime's ARN
another way, and for a valid message whose sweep is not run (see "Background
sweeps", step 1). So a history holds no `sweep` event without a `sweep`
number, and one event for each sweep.

A history written before these rules can hold both: a `sweep` event with
outcome `failed`, no `sweep` number and a request id of its own (an invalid
message), and two events for one sweep (a message that was delivered
twice). They stay as they are, and the counts in `sweeps` count a sweep
once. A contain recorded before its result listed its sweeps has no
`sweeps_scheduled_numbers`; for such a contain every sweep number is
admitted, as it was when that contain was made.

## Read endpoint (read API, any mapped role)

### `GET /agents/{id}/containment`

Returns `ContainmentView`. `state` is read fresh from the Runtime's resource
policy, so it is correct immediately after an action. The `flags.contained`
field of the list, `GET /agents`, can lag by the cache lifetime (30 seconds
by default). On the page of the one agent, `GET /agents/{id}`, it follows a
contain or a release that was carried out: that read loads the inventory
again when the Runtime's history holds such a decision that is newer, at
most once in 15 seconds.
`state` is `unknown` when the policy cannot be read or the agent's account has
no reader (the normal case for an agent the organization registry detected in
an account that is not a cell); `detail` then says which, for example "There
is no reader in this agent's account, so its containment state cannot be
read." `enabled` is false for such an agent, so offer no action. `contained_at`
is set while the agent is contained through the portal; a Runtime contained by
other means shows `contained` with it null.

`detail` is also set in three cases in which the state is known or cannot be
asked for. Show it as it is:

- `not_contained` with a statement under the portal's Sid that is not the
  one the portal writes (see "Contained means the portal's statement,
  whole"; it may or may not deny invocation). Offer
  Contain as usual: it replaces that statement.
- `unknown` for a registration that names its Runtime by another spelling of
  its ARN: the portal reads a policy and a history only under the ARN it
  builds itself, so neither was read.
- `contained` when who contained the agent could not be established, because
  the Runtime's history holds more than 2000 events since its last contain
  or release among those a release reads (see "The Runtime's history": no
  number of sweeps or repeated contains brings that about any more).
  `contained_by` and `contained_at` are then null, and a release
  is refused (409) for the same reason.

`events` holds the newest 200 events of the Runtime's history.
`events_truncated` is true when the history holds older ones. Who holds the
containment and `partial` are not affected by that: they
are read back to the event that began the containment, however many events
came before it. `sweeps` and `quiet_at` are read back to that event too, and
at most 2000 events: for a containment with more sweeps and repeated
contains than that since it began, they describe the newest 2000.

**The incident record is for responders.** Who contained the agent, why, and
the history of attempts (`contained_by`, `contained_by_label`, `reason`,
`events`) are returned only to a caller whose role can contain or release
(`security`, `platform`, `sre`). Every other mapped role gets them as null and
an empty list, and still gets `state`, `enabled`, `contained_at`, `partial`,
`contained_by_me`, `sweeps`, `quiet_at` and the two delays. Show "Contained
since <time>" to those roles and no history table.

The role that decides this is the one the caller's token gives. The read
API verifies the token itself, as the containment function does, and takes
nothing about the caller from the invocation event.

Status codes: 200; 401; 403 (no mapped group); 404 (no such agent); 422
(malformed id); 503 (the identity provider's signing keys could not be
fetched, so the caller could not be verified and nothing was read).

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
| 401 | No bearer token, or one the function does not accept. The function verifies the token itself | `"Not authenticated"` |
| 403 | No mapped group; or the role, tenant or two-person rule refused it | The rule's reason, for example `"contain requires the security, platform or sre role; principal holds 'developer' (CON-01-N)"` or `"the person who contained the agent cannot release it - two-person rule (CON-03-N)"` |
| 404 | No such agent; also any path or method this function does not serve | `"Agent not found"` or `"Not found"` |
| 409 | Containment is not enabled for the agent's cell; the registration names no Runtime, or names it by another spelling of its ARN; the existing policy cannot be parsed; on a release, who contained the Runtime could not be established (its history holds more than 2000 events since its last contain or release) | A sentence to show the user |
| 422 | The body or the id is invalid; `runtime_arn` is missing, is another Runtime's, or is not this Runtime's ARN as the portal writes it (its partition, Region and account must be those of the Runtime's cell) | A list of `{ loc, msg, type }` |
| 500 | The function is not configured | `"Portal configuration error: ..."` |
| 502 | An AWS call failed part-way | A sentence that says what was and was not done, for example `"The deny statement could not be written (AccessDeniedException). Nothing was changed."`, or, when the write failed in a way that may have applied it all the same (a server error, throttling, no answer), `"... It is not known whether the statement was written. Sessions were not stopped."`. The body also has `steps` (the same `ContainmentStep` list), `action` and `request_id` |
| 503 | The audit trail could not be written or read, or the identity provider's signing keys could not be fetched, so nothing was done | A sentence to show the user |

Notes for the UI:

- **A 200 can still carry bad news about sessions.** Containment succeeds as
  soon as the deny statement is verified. `partial` is true when the session
  step was not clean: a source of session ids could not be read, some sessions
  could not be stopped, or the time limit ran out. The `sessions` step then
  has status `partial` (or `failed` when no source could be read) with a
  sentence in `detail`, and `sessions` has the counts. Show the steps. The
  agent is contained regardless: the deny statement blocks further
  invocations, including on sessions that are still running.
- **Finding no session is normal.** An agent that writes no output (and, with
  the traces option, emits no traces) has nothing to find; `found` is 0 and
  the step is `done`.
- **There are no intermediate states.** The actions are synchronous; `state`
  is never "containing" or "releasing". A request can take up to about 25
  seconds when many sessions are stopped.
- **The request does not wait for the background sweeps.** A contain answers
  as soon as its own steps are done, and `sweeps_scheduled_in_seconds` says
  when the sweeps will run. To show their progress, re-read
  `GET /agents/{id}/containment` while `sweeps.done` is less than
  `sweeps.scheduled` (every 15 to 30 seconds is enough; the last sweep runs
  15 minutes after the contain): "Background sweeps: 1 of 2 done", and once
  `quiet_at` is set, "No running session since <time>".
- **`partial` and `quiet_at`.** `partial` describes the contain request and
  does not change afterwards. `quiet_at` is the later and stronger statement:
  once it is set, show it in place of the partial warning.
- **A 502 always says what state the agent is in.** After a 502, re-read
  `GET /agents/{id}/containment` and show its `state`. After a write that may
  have been applied, the caller is on record as the one who contained the
  agent: if the view then shows `contained`, `contained_by_me` is true and
  someone else has to release it.
- **A contain that did nothing because it came too soon** is a 200 with
  `retry_after_seconds` set. Say that the background sweeps are still
  running, and offer "Stop remaining sessions" again once that time is over.
  If a sweep is still at work then, the answer is the same again with a
  shorter time; the view's `sweeps.done` reaching `sweeps.scheduled` says
  that none is.
- 403, 409 and 502 answers carry `request_id`. What is in the Runtime's
  history, and what is in the function's log under that `request_id`:
  - **In the history:** every contain and release that was allowed, every
    failure, the two-person refusal (`CON-03-N`) and the refusal for a
    tenant that changed (`CON-06-N`). A refusal is written once for each
    person, rule and containment, and logged after that.
  - **In the log only:** a refusal for the role (`CON-01-N`, `CON-02-N`),
    for the tenant (`CON-04-N`, `CON-05-N`), for a cell that did not enable
    containment, and for a history too long to establish who contained the
    Runtime. Such a caller has no part in the Runtime. Written into its
    history, each attempt would add an event to a history that is never
    shortened, and anyone signed in with a responder role of another tenant
    could fill it.
  - So `events` does not list those refusals. A history shows fewer
    refusals than before this rule.
- After a successful action, refresh `GET /agents/{id}/containment`.
- A caller without the role gets 403 whether or not the agent exists.

Rule identifiers in `detail`: `CON-01-N` (role for contain), `CON-02-N` (role
for release), `CON-03-N` (two-person rule), `CON-04-N` (tenant not held),
`CON-05-N` (the agent's tenant cannot be determined; `platform` only),
`CON-06-N` (release: the Runtime's tenant changed since it was contained, or
was not known then; `platform` only).

**A long history.** A contain looks at the newest 200 events of each range
of the Runtime's history, one request each, to see whether it was contained
a moment ago and whether somebody holds it; it does its work whatever those
reads say, and also when they fail, so it does not depend on the history's
length. (A contain of a Runtime that is already contained reads further only
when the newest events of an old history do not say who holds it, and then
as far as a release reads.) A release reads the events that can change who
holds the containment, from the newest back to the one that settles it, and
at most 2000 of them. If none of them settles it, the release is refused
with 409 and the Runtime stays contained: who contained it is not known, and
that must not read as "nobody". The statement can then be removed only in
the cell account, outside the portal. Someone with no part in the Runtime
cannot add an event to its history, and a refusal is written once for each
person, rule and containment. A responder of the Runtime's own tenant who
contains it again and again adds nothing to what a release reads: those
contains and their sweeps are written into the other range.

## Routing

The containment function serves only the two `POST` routes above and answers
404 for anything else. The read API serves the `GET` and answers 405 for the
two `POST` routes. The registrar and approver functions answer 404 for all
three. The sweeper function serves no route. The sweep queue invokes it, and
so can any principal of the Platform account that holds
`lambda:InvokeFunction` on it. That is why the sweeper treats every message
as untrusted input, why it runs and records only a sweep that a contain on
record scheduled, and why it assumes the cell's containment role with a
session policy that leaves out writing and deleting a resource policy
(IAM_ACTIONS.md, section 7).

As the blueprint deploys the portal:

- Only the containment function's role can send, receive, delete, change the
  visibility of or purge a message of the sweep queue. The queue's own
  policy denies those five to every other principal, an administrator of
  the account included, so nobody else can put a message on the queue or
  take one off it. That is the queue's messages, not the queue: a principal
  that may change the queue's attributes or delete it (the role that deploys
  the portal, for one) can still make scheduled sweeps disappear, for
  example by shortening how long the queue keeps a message.
- Two alarms watch the sweeps: one when a message could not be processed
  twice and was set aside in the dead-letter queue, one when the oldest
  message of the queue has waited for more than an hour.
- Contain and release each have a request budget of their own at the API:
  100 requests per second with a burst of 200. No other route can use it
  up, so a flood of reads does not keep a responder from containing an
  agent. A request is counted before the function decides who may act, so
  the budget is set far above what responders need.
- Up to five sweeps run side by side, so that one Runtime with very many
  sessions does not hold up the sweeps of every other.

CORS: with `PORTAL_ALLOWED_ORIGINS` set, the containment function allows
`POST` with the request headers `authorization` and `content-type`.
