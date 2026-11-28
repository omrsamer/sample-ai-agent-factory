# Agent Factory Portal API

Back end of the Agent Factory Portal, the product surface for the
blueprint's planes (developer experience, platform control, assurance and
operations). It serves blueprint data in the response shapes the portal front
end (`../web`) already uses.

The bundle holds five Lambda functions. The first four have an IAM role
each; the sweeper runs under the containment function's role:

| Handler | Purpose |
| --- | --- |
| `handler.handler` | The read API. Every route is a `GET` |
| `registrar_handler.handler` | Create, update, submit and delete agent records |
| `approver_handler.handler` | Approve or reject a submitted agent record; retire a record; attest its periodic review |
| `containment_handler.handler` | Contain or release an agent's Runtime |
| `sweep_handler.handler` | The sweeper: stops the sessions a contained Runtime still has, in the background. The sweep queue invokes it; it serves no route |

The read API is read-only by construction:

- Every route is a `GET`. Any other method is answered with `405` before a
  route or dependency runs.
- Its code calls only list, get, describe and query operations, plus
  `logs:StartQuery` to run read-only CloudWatch Logs Insights queries, and it
  does not import the action code. `tests/test_readonly.py` enforces this and
  keeps [IAM_ACTIONS.md](IAM_ACTIONS.md) exact for every role.
- Workstream cells are changed only by their pipelines. The portal reads each
  cell through a reader role, so central visibility does not become central
  write access.

## Endpoints

All under `/api/v1`. Everything except `/health` requires an authenticated
caller with a mapped role.

| Path | Source |
| --- | --- |
| `/health` | Liveness only. No authentication, no data, no configuration |
| `/users/me` | Validated token claims and `PORTAL_GROUP_ROLE_MAP` |
| `/agents`, `/agents/{id}` | AWS Agent Registry records with the `agenticai.agent-governance/1.0` document, merged with Amazon Bedrock AgentCore runtimes found in cell accounts. A runtime that no record references is returned with `lifecycle_state` and `registration` set to `discovered`. A registered agent's `name` is its agent id; the registry record name is in `record_name` |
| `/agents/{id}/runtime` | Runtime status from the cell account |
| `/agents/{id}/deployments` | Runtime versions of the agent's runtime |
| `/agents/{id}/traces` | CloudWatch Logs Insights over the `aws/spans` log group of the cell account, one row per trace |
| `/agents/{id}/metrics` | `GetMetricData` on `AWS/Bedrock-AgentCore` (invocations, errors, throttles, latency) and token usage read from spans |
| `/agents/{id}/evals/runs` | Release evidence: recent executions of the cell's Workload pipeline with the `EvaluationGate` action result |
| `/agents/{id}/mcp-grants` | Derived, read-only edges from the agent to Tool Gateways |
| `/mcp-servers`, `/mcp-servers/{id}` | One per AgentCore Gateway that a cell reader read or the organization registry detected. Tools are the gateway targets joined with registry tool records (`agenticai.tool-governance/1.0`). A gateway that no reader read has `reader_status` other than `ok` and no tools; see "Gateways no reader read" |
| `/mcp-servers/{id}/policies` | Policies of the gateway's AgentCore Policy Engine. Cedar text is returned as stored and marked not editable. For a gateway no reader read: no policies, and `warnings` says why |
| `/mcp-servers/{id}/policy-enforcement` | `none`, `log_only` or `enforce`, from the gateway's policy engine configuration. `unknown`, with a `detail` sentence, for a gateway no reader read |
| `/mcp-servers/{id}/grants` | The same derived edges, seen from the gateway. Empty for a gateway no reader read |
| `/governance-graph` | Nodes `group`, `agent`, `mcp`; edges `access` (owner group to agent) and `can_call` (agent to gateway). No `user` nodes in the default profile |
| `/principals/{id}`, `/governance-graph/principals/{id}` | Detail of an owner group that appears in the graph |
| `/observability/settings`, `/observability/metrics` | CloudWatch back end marker; fleet metrics per agent |
| `/guardrails`, `/guardrails/{id}` | Amazon Bedrock guardrails in the platform account. Filtered to those that carry the configured tag when one is set; otherwise all of them |
| `/fleet/health` | Per cell: CloudWatch alarms by name prefix, reduced to `healthy`, `needs_attention`, `critical` or `no_data`. An unreachable cell is reported, not fatal |
| `/fleet/summary` | Counts of agents by inventory state, lifecycle, risk level and flag, and of gateways by policy mode (`gateways_by_policy_mode`: `enforce`, `log_only`, `none`, and `unknown` for the gateways no reader read) |
| `/agents/export` | The inventory as a CSV or JSON download |
| `/agents/{id}/containment` | Whether the agent's Runtime is contained, by whom, and the containment events |
| `/agents/{id}/evidence` | One JSON document about the agent for an auditor, as a download |
| `/omni/observed-services` | Services the CloudWatch Omni Context Graph observes in the portal's own account, marked registered or not |
| `/catalog/models` | `PORTAL_MODEL_ALLOWLIST` |
| `/catalog/tools` | Registry tool records |
| `/registrations` | Agent governance records in the registry, with `status` and `tenant_id` filters |
| `/registrations/{record_id}` | One record, with who created, submitted, decided and last reviewed it (from the audit trail), and its effective review date |
| `/registrations/{record_id}/history` | The newest 200 events of the record's audit trail, newest first, and whether there are older ones |

**How fresh a read is.** The lists are served from an inventory that is
cached in the process for `PORTAL_CACHE_TTL_SECONDS` (30 by default), so a
list can be that far behind a decision. The list of agents stays as it was
cached. Three reads do not wait for the cache. `/agents/{id}/containment`
reads the Runtime's policy when it is asked, and `/registrations/{record_id}`
reads the record itself. `GET /agents/{agent_id}` reflects a decision about
that agent that was taken a moment ago: a person who has just retired a
registration or contained an agent opens the agent's page and is not shown
the state from before. For that it asks the audit trail first, with one
request for each of the agent's two histories (its registration's and its
Runtime's containment), for the newest 20 events of each. When one of them
is the result of a decision that was carried out (outcome `allowed` or
`unchanged`) and is newer than the inventory, the inventory is loaded again
and the answer comes from that. A refusal, a failure, an intent and a
background sweep change nothing, so they cause no load. The load reads every
cell, so it happens at most once in 15 seconds per execution environment, a
limit this read shares with the evidence document. Inside that time the
audit trail is not asked and the answer is the cached one, as it is when the
trail cannot be read or the load fails. A registration that was made a
moment ago, which the cached inventory does not hold yet, is found the same
way, by its own id.

Inventory states. Every agent carries `inventory_state` and `detection_sources`:

| `inventory_state` | Meaning |
| --- | --- |
| `registered_and_detected` | A registration whose Runtime at least one source detects |
| `registered_only` | A registration whose Runtime nothing detects, or that names no Runtime |
| `detected_only` | A Runtime with no registration. Its `lifecycle_state` stays `discovered` |

The sources are `cell_reader` (the reader role of a configured cell listed the
Runtime) and `organization_registry` (a record of the discovery registry names
it). The join is on the Runtime ARN, so a Runtime seen by both is one agent. A
Runtime that only the discovery registry sees is listed with its ARN, account,
Region, name (from the ARN) and inbound authorizer. This is the normal case
for an account the portal has no cell in. Such an agent has
`reader_status: "none"`, and every per-cell read degrades instead of failing:
its Runtime status is `unknown`, its traces, metrics and containment state
answer with "There is no reader in this agent's account, ...", and its
`inactive` and `contained` flags are null. `account_alias` is the configured
alias of the agent's account, or null when none is configured (`account_id`
is always there). If the discovery registry cannot be read, the inventory is
still served from the cell readers.

Gateways no reader read. The organization registry also detects Tool
Gateways. One that a cell reader read as well is one gateway, with both
sources in `detection_sources`. One that only the registry detected is listed
with what the detection says and nothing more:

- **What it has:** its id and ARN, a name taken from the ARN, the account
  (`account_id`, and `account_alias` when one is configured), the Region, and
  the authorizer type and protocol from the detection's provenance (null when
  the registry's record does not carry them). `detection_sources` is
  `["organization_registry"]` and `lifecycle_state` is `discovered`.
- **What it does not have:** targets, a tenant, a status, a policy engine.
  `cedar_enforcement_mode` is `unknown`, never `none`: "no policy engine" is
  not claimed for a gateway whose policy cannot be read. The fleet summary
  counts it under `unknown`, and an agent that names it is not given the
  `GATEWAY_POLICY_NONE` reason.
- **Why, in `reader_status` and in a sentence (`detail`):** `none` ("There is
  no reader role in this gateway's account, so its targets, its policy engine
  and its policies cannot be shown."), `unreachable` (the reader role could
  not be used) or `not_listed` (the reader works but did not list it; it may
  have been deleted since it was detected). A gateway a reader read has
  `reader_status: "ok"`.
- **It never takes the place of a gateway a reader read.** A detection is
  keyed by an ARN that whoever registered it wrote. One that carries the id
  of a listed gateway under another ARN (another spelling, another account)
  is left out: what a reader read stands, in the list and under
  `/mcp-servers/{id}`.
- **Its three sub-resources answer 200, never an error:** `/policies` with no
  policies and the sentence in `warnings`, `/policy-enforcement` with
  `unknown` and the sentence in `detail`, `/grants` with an empty list.
- **In the governance graph** it is a node (its metadata carries
  `reader_status` and `enforcement_mode: "unknown"`), and no edge is drawn to
  it, even when a registration names it: an edge says who can call a gateway
  and whether a policy stands between, and neither is known. The agent's own
  `/agents/{id}/mcp-grants` still lists the gateway its registration names.

Things to know about the data:

- Cost is not available from CloudWatch. Every `cost_usd` is `0` and metrics
  responses carry `cost_available: false`.
- Trace and metric queries wait a bounded time. If a query is still running,
  the response carries what is available and a `warnings` list.
- Grants are derived, not stored. A registered agent links to the gateway named
  in its record. A discovered runtime links to a gateway only when its
  configured gateway URL, or its tenant, agent and environment tags, match one.
- The default Tool Gateway authorizes with AWS IAM, so there are no per-user
  grants to show.
- `/observability/metrics` with `scope=platform` (the default) requires the
  `platform` role and is `403` otherwise. `scope=tenant` is open to every
  mapped role. Both return the configured fleet, because the default profile
  has no per-tenant membership.
- `stage` on `/agents/{id}/runtime` and `/agents/{id}/deployments` selects an
  environment. An agent has one environment, so any other value answers
  `not_deployed` or an empty list.
- `/fleet/health` shows `accountAlias` from the cell configuration. Without
  one it shows a masked label (`account-` and the last four digits), never the
  full account id. `agent_ref` is the `Agent.id` to link to, when known.

The agent governance document is defined in
[schemas/agent-governance-1.0.json](schemas/agent-governance-1.0.json).

## Flags and risk

Every agent carries `flags`, `risk` and `obligations_closed`. Each flag is
`true`, `false`, or `null` when it cannot be known. On an agent whose
`obligations_closed` is true (a retired registration with nothing deployed,
see below) the flags `unmanaged`, `ownerless`, `review_overdue` and `inactive`
are null because they do not apply, not because they could not be read.

| Flag | True when | Null when |
| --- | --- | --- |
| `unmanaged` | The agent has no registration in status APPROVED (including every `detected_only` agent) | never |
| `ownerless` | The registration names no owner group, or `PORTAL_OWNER_GROUPS` is set and the owner group is not in it. The accountable owner is the owner group; `sponsor` and `contact` are optional and do not enter this flag | the agent has no registration |
| `review_overdue` | The effective review date is before today (UTC): the date of the latest review attestation, else the registration's `review_by`. No date means not overdue. Always false for a retired registration, which can no longer be reviewed | the agent has no registration |
| `inactive` | The Runtime had no invocation in the last `PORTAL_INACTIVE_DAYS` days (default 30), from its CloudWatch invocation metric read through the cell reader | the metric could not be read, or no cell reader covers the Runtime |
| `contained` | The Runtime's resource policy holds the portal's containment statement | the policy could not be read, or no cell reader covers the Runtime |

`risk` is `{ level, reasons: [{ code, severity, detail }] }`. It is computed by
one pure function, `portal_api/risk.py`, from facts the API already has. There
are no weights and no scores:

- Each rule below looks at one fact (two for the rules that also need a Runtime to be known). When it applies it adds one reason with a fixed severity.
- Every reason shown is true of that agent. A rule names the cause it found: an agent nobody registered (`UNREGISTERED`, high) and a registration that waits for an approver (`REGISTRATION_NOT_APPROVED`, medium) are different findings. The `unmanaged` flag is true for both; it is a count for the fleet tile, not a reason.
- `level` is the highest severity among the reasons (`critical` beats `high` beats `medium` beats `low`), and `low` when no rule applies.
- A fact that is not known triggers no rule, so an unknown never raises or lowers the level.
- Reasons are listed most severe first, and in the order of this table within a severity.
- One guard stands before the table (`closed` in `portal_api/risk.py`, the one place the condition is written). A retired registration with no Runtime known is closed: no rule applies to it, its level is `low` and it has no reasons. Retirement is terminal, so a finding about what the record says (its owner group, its sponsor, its evaluation) could never be cleared, and the agent would stay in the attention list until someone deleted the record. With nothing deployed there is nothing left to do. Such an agent has `obligations_closed: true`, the four flags above are null for it, the fleet summary counts none of its flags (neither as set nor as unknown), and it is not in `needs_attention`.
- Closed takes an agent off every list that asks for attention, so it is not granted while the portal is blind for a passing reason. When the reader of the Runtime's account exists and could not be used for this inventory (`reader_status: "unreachable"`), a retired registration is not closed: the rules apply to it as to any registered agent whose Runtime could not be read, and the fleet summary already says that a cell could not be read. When the reader answers again it is closed if no Runtime is found, and gets `REGISTRATION_DEPRECATED` if one is. An account with no reader at all, and a registration that names no Runtime, do not keep an agent open: nothing would ever close it.
- The guard does not cover the two neighbouring cases. A retired registration whose Runtime is still deployed keeps `REGISTRATION_DEPRECATED` (high) and every other rule, because someone still has to remove the Runtime. A rejected registration keeps its findings too: it can be corrected and submitted again.

| Code | Severity | Applies when |
| --- | --- | --- |
| `RISK_CLASS_UNACCEPTABLE` | critical | The registration's risk class is `unacceptable` |
| `INBOUND_AUTH_NONE` | critical | The Runtime's inbound authorizer is `NONE` (unauthenticated calls) |
| `UNREGISTERED` | high | The agent has no registration at all (every `detected_only` agent) |
| `REGISTRATION_REJECTED` | high | The registration's status is `REJECTED` and a detection source still sees its Runtime |
| `REGISTRATION_DEPRECATED` | high | The registration is retired (status `DEPRECATED`) and a detection source still sees its Runtime |
| `RISK_CLASS_HIGH` | high | The registration's risk class is `high` |
| `DATA_RESTRICTED` | high | The data classification is `restricted` |
| `OWNERLESS` | high | The registration names no owner group |
| `OWNER_GROUP_NOT_IN_ROSTER` | high | `PORTAL_OWNER_GROUPS` is set and the registration's owner group is not in it |
| `EVALUATION_FAILED` | high | The recorded evaluation verdict is `failed` |
| `CELL_HEALTH_CRITICAL` | high | The fleet-health state of the agent's cell is `critical` |
| `REGISTRATION_NOT_APPROVED` | medium | The registration exists but is not approved yet: `DRAFT`, `PENDING_APPROVAL`, or being created or updated |
| `GATEWAY_POLICY_NONE` | medium | A Tool Gateway the agent is linked to has no policy engine |
| `GUARDRAIL_NOT_CONFIGURED` | medium | The Runtime's configuration names neither a guardrail nor the inference gateway |
| `DATA_CONFIDENTIAL` | medium | The data classification is `confidential` |
| `REVIEW_OVERDUE` | medium | The `review_overdue` flag is true |
| `EVALUATION_NOT_RUN` | medium | The verdict is `not_run`, or a registered agent has no recorded verdict |
| `CELL_HEALTH_NEEDS_ATTENTION` | medium | The fleet-health state of the agent's cell is `needs_attention` |
| `SPONSOR_MISSING` | low | The registration names neither a `sponsor` nor a `contact` |
| `GATEWAY_POLICY_LOG_ONLY` | low | The weakest policy mode among the agent's Tool Gateways is `log_only` |
| `INACTIVE` | low | The `inactive` flag is true |

Notes on the facts: the Tool Gateway policy mode is the weakest among the
gateways the agent is linked to (`none`, then `log_only`, then `enforce`), and
is unknown for an agent with no linked gateway. `contained` is a flag only and
does not change the risk level.

Guardrail coverage is derived from the names of the Runtime's environment
variables, read through the cell reader. In the blueprint a guardrail is
applied to every model call at the inference gateway, so a Runtime counts as
covered when its configuration names either of these with a non-empty value:

- a guardrail: any variable whose name contains `GUARDRAIL`, for example
  `AGENTCORE_GUARDRAIL_ID` (set by the blueprint's generated agent) or
  `GUARDRAIL_ID`;
- the inference gateway: `AGENTCORE_INFERENCE_GATEWAY_URL`, the one name the
  blueprint uses for the platform inference gateway URL.

A Runtime that names neither gets `GUARDRAIL_NOT_CONFIGURED`. The fact is
unknown, and the rule silent, when the Runtime's configuration cannot be read.
Only names and emptiness are looked at: no environment value is ever returned
or logged.

`GET /fleet/summary` counts agents by inventory state, lifecycle and risk
level, counts each flag (and for how many agents it is unknown), counts
gateways by policy mode, and lists the agents at risk level high or critical
(`needs_attention`, at most 20, most severe first). Counts are never null: a
flag that could not be evaluated for an agent is counted in `flags_unknown`.
An agent whose `obligations_closed` is true is counted among the agents, in
its inventory state, its lifecycle and at risk level `low`, and in no flag
count at all.

`GET /agents/export?format=csv|json` returns one row per agent as a download.
The last two columns are `review_by` (the effective review date) and
`last_reviewed_at`; new columns are added at the end so that existing positions
do not move. The row of a retired registration with nothing deployed has
`lifecycle_state` `deprecated`, no `runtime_arn`, risk level `low` and empty
flag cells, which there mean "does not apply".
In CSV, a cell that starts with `=`, `+`, `-`, `@` or a tab is prefixed with a
single quote so that a spreadsheet does not run it as a formula; lists are
joined with `;`; an unknown flag is an empty cell. The export never contains a
raw account id outside an ARN: accounts appear as the cell's `accountAlias` or
a masked label. The response exposes `Content-Disposition` to cross-origin
scripts so the front end can read the file name.

## Containment

Specified for the front end in [CONTAINMENT_CONTRACT.md](CONTAINMENT_CONTRACT.md).

- **What it changes.** One statement, Sid `AgenticAIPortalContainment`, in the
  Runtime's resource policy: `Effect: Deny`, `Principal: "*"`, and `Resource`
  set to exactly the Runtime's ARN (the service accepts only a single resource
  equal to the policy's own). An invocation through any endpoint is authorized
  against the Runtime as well, and an explicit deny wins, so the one statement
  covers every endpoint.
- **What counts as contained.** The statement is recognised by all of it,
  not by its Sid (`is_containment` in `portal_api/containment_policy.py`):
  the portal's Sid, `Effect: Deny`, `Principal: "*"`, `Resource` the
  Runtime's ARN, `Action` a list that holds the two core invoke actions and
  nothing but invoke actions, and no other element (no `Condition`,
  `NotAction`, `NotPrincipal`, `NotResource`). Whoever can write a Runtime's
  policy can put a statement under the portal's Sid that denies nothing, and
  a check of the Sid alone would then report the Runtime as contained and a
  contain as already done. Such a statement is not containment: the read
  side says `not_contained` with a sentence, a contain replaces it and says
  so (`replaced_foreign_statement`), a release leaves it and says that it is
  there, and a sweep stops nothing. `Principal` must be the plain `"*"`: it
  is the one form that covers a Runtime whose callers sign in with OAuth
  tokens. `state` in that module is the one function that reads a policy
  this way; contain, release, the read API, the sweeper and the evidence
  document all go through it.
- **Which actions it denies.** The six invoke actions the service documents
  for a Runtime policy: `InvokeAgentRuntime`, `InvokeAgentRuntimeCommand` and
  the per-user, shell and WebSocket variants. The service accepts that list
  (measured live). Should it ever reject it, the function writes the statement
  with the two core actions (`InvokeAgentRuntime`,
  `InvokeAgentRuntimeCommand`) instead, and the response and audit event say
  so (`denied_actions`).
- **Enforcement takes time, and the two directions differ.** The service
  applies a policy change host by host. Measured on a live Runtime under
  steady calls: after contain an occasional invocation still succeeded for up
  to 52 seconds; after release, calls were still refused for about four and
  a half minutes. Responses report the new state once the statement is
  verified and carry `enforcement_delay_seconds` (90 for contain, 300 for
  release; `portal_api/containment_timing.py`). The function never invokes
  the Runtime to test the block; its role cannot.
  Every other statement is kept as it was (`portal_api/containment_policy.py`,
  pure functions). Release removes exactly that statement and deletes the
  policy only if nothing else remains.
- **Sessions.** No API lists a Runtime's sessions, so the session ids of the
  last eight hours (the maximum session lifetime) come from the names of its
  session log streams, `runtime-logs-<session id>` in
  `/aws/bedrock-agentcore/runtimes/<runtime id>-<endpoint>` for each of the
  Runtime's endpoints. Any agent that writes output has them, and no log event
  is read. A cell can opt in to a second source (`containmentSpans` on the
  cell): the Runtime's spans (`attributes.session.id`), which finds a session
  of an instrumented agent that wrote no output. It is off by default because
  it needs a Logs Insights query permission on the cell's containment role,
  and a role that can run a query can read span content. Each session is
  stopped, most recent first, at most 1000 per action and within a time
  budget. A list that a limit cut never reads as complete: the result is
  partial and says that more sessions may be running. A session that is
  unknown or already ended counts as needing no stop. With both sources, if
  one cannot be read the other is used and the response names the one that
  failed; if no source can be read, containment still holds and the response
  and audit event say that the stop was not performed and why.
- **Background sweeps.** A request has seconds, so a contain also leaves up
  to three messages on a queue (`PORTAL_SWEEP_QUEUE_URL`), and the sweeper
  function runs one sweep per message: at once (only when the request left
  something undone), after 120 seconds (past the 90 seconds a host can take
  to apply the deny) and after 900 seconds (the longest delay a queue message
  can have). The delays and the stop rate are in
  `portal_api/containment_timing.py`. A sweep
  (`portal_api/actions/sweeper.py`) first reads the Runtime's policy and
  stops nothing unless the portal's statement is there, so a release cancels
  nothing and a late sweep is harmless. It then lists every session of the
  lookback window (no limit on their number, only on the 15 minutes the
  function has), stops them at no more than 20 per second, and writes one
  `sweep` event with the counts and the time it took. While it stops
  sessions it reads the policy again every 30 seconds, so a release also
  ends a sweep that is running. The message
  (`portal_api/sweeps.py`, pure) holds a Runtime ARN, the agent id, the
  sweep number and the contain's request id, and the sweeper treats it as
  untrusted input: it checks the shape, finds the cell and its containment
  role in its own configuration, accepts the Runtime's ARN only as the portal
  builds it for that cell, and never takes a role, an account or a Region
  from the message. It assumes the cell's containment role with a session
  policy that allows only what a sweep does (read the policy, list endpoints
  and log streams, stop a session, and the two query actions in a cell with
  the spans option), so its session cannot write or delete a resource policy
  whatever its code does (`session_policy` in
  `portal_api/actions/sweeper.py`). Each function assumes a cell's role
  under a session name of its own (`portal-reader`, `portal-containment`,
  `portal-sweeper`), so the cell's CloudTrail tells their calls apart. A
  message it cannot validate is logged and dropped, and leaves no event.
  A valid message proves nothing either, since whoever can invoke the
  function writes any request id and sweep number into one. So before a
  sweep is run the sweeper reads the Runtime's history back to the contain
  the message names: that contain must be on record and have scheduled
  sweeps, this sweep must be due (it is run no earlier than 30 seconds
  before) and must not have left its event, and no later containment may
  have taken that contain's place. It then claims the sweep with one
  conditional write (`claim_sweep` in `portal_api/actions/audit_writer.py`),
  so that a second delivery or a second invocation at the same moment cannot
  run it as well. That is at most three events for one contain, whoever
  sends or replays messages or invokes the function: a history is never
  shortened, and a release reads it back to the contain it undoes. The
  worst a forged or replayed message can do is start, at the time it is due,
  a sweep that a contain scheduled. The containment view
  reports `sweeps` (scheduled, done) and `quiet_at`, the end of the first
  complete sweep that started after the 90 seconds. Without the queue
  variable the feature is off and a contain is exactly what it was.
- **What a sweep costs.** No API says which sessions of a Runtime are live,
  so every sweep calls stop once for every session of the lookback window,
  ended or not. Measured on a live Runtime with about 430 sessions in eight
  hours, of which none or one was running: 430 stop calls and 21.5 to 22
  seconds per sweep, which is the cap of 20 per second plus about half a
  second of listing; the service did not push back. On a busy Runtime that
  is the cost of each of the three sweeps.
- **A contain repeated too soon.** A contain of an agent that is already
  contained does its work again (stops sessions, schedules sweeps) only
  when the sweeps of the last one are over: no sooner than 15 minutes after
  the last contain that scheduled sweeps, and not while one of those sweeps
  has yet to leave its event (a sweep that has left none 30 minutes after
  its contain is given up). Until then the contain reads the policy, and if
  the portal's statement is there it answers `unchanged` at once with
  `retry_after_seconds`: no session is listed or stopped and nothing is
  scheduled. The history gets one result for it, once for each person who
  asks again in that time, with no session counts, which is how the rule
  tells it from a contain that did its work. Each contain that does its work holds
  a slot of the containment function for up to about 20 seconds and puts up
  to three sweeps on the queue, so repeating one without a pause took the
  function and the sweeper from every other tenant. What the request left
  undone, its sweeps do. A contain that scheduled no sweep (no queue, or the
  queue could not be reached) is never too soon to repeat: containing again
  is then the only way to go on. The figures are in
  `portal_api/containment_timing.py`, the rule in `repeat_too_soon` in
  `portal_api/sweeps.py` (pure).
- **Who.** `portal_api/actions/containment_rules.py` (pure): contain needs
  `security`, `platform` or `sre`; release needs `security` or `platform` and a
  different person from the one who contained it; the caller must hold the
  agent's tenant.
- **A tenant that changed.** A release also needs the Runtime's tenant to be
  the one it was contained under, which its contain event records
  (`CON-06-N`). In a shared account the tenant comes from a tag, and whoever
  can set that tag could otherwise move a contained Runtime into their own
  tenant and release it there. A Runtime whose tenant changed, or was not
  known when it was contained, is released by `platform` only. The tag
  itself is protected outside the portal: in a shared account, deny
  `TagResource` and `UntagResource` on the `tenant-id` key to everyone but
  the cell's pipeline.
- **A write that may have been applied.** If writing the statement fails
  with a refusal (a 4xx that is not throttling), nothing was changed. If it
  fails with a server error, with throttling after the SDK's retries, or
  with no answer at all, the service may have applied it. The result is
  then recorded with `status_after` `unknown`, which names the caller as the
  holder: if the statement is in place, they are not the one to remove it.
- **Which tenant.** `tenant_for` in the same module: the tenant is decided by
  where the Runtime runs (the cells configured for its account and Region),
  never by a registration, approved or not. One tenant there: that tenant,
  and nothing is read. Several (a shared account): the value of the Runtime's
  own `tenant-id` tag when it names one of them, read with the cell's
  containment role after the caller's role has passed. Under this blueprint
  only the cell's pipeline changes a Runtime, so the tag is the cell's word,
  not a registration's. No tag, a tag for a tenant the account does not host,
  or a tag that cannot be read: the tenant cannot be determined and only
  `platform` may act. A registration that names another tenant's Runtime
  therefore gives nobody authority over it.
- **Where.** Everything in the cell is done by assuming the cell's
  `containmentRoleArn` with the cell's `externalId`. A cell without one
  cannot be contained (409).
- **Resolving the agent.** A registered agent's Runtime ARN is read from its
  registry record, never taken from the request. An agent with no
  registration is addressed by its Runtime id.
- **One ARN per Runtime.** The service answers for more than one spelling of
  a Runtime's ARN: another partition string reads the same resource policy
  (measured live). The history is keyed by the ARN and the two-person rule
  reads the history, so a second spelling would be a second, empty history,
  under which the person who contained a Runtime could release it. The
  portal therefore never uses an ARN as a caller, a registration or a queue
  message wrote it. It builds the ARN itself (`portal_api/arns.py`, pure):
  the partition from the cell's role ARN, the Region and the account from
  the cell, and the Runtime id as given, which the service treats as case
  sensitive. Every call in the cell and the key of the history use that ARN.
  A `runtime_arn` in a request must be equal to it, character for character,
  or the request is refused with 422 before anything is read; a registration
  that spells it another way is not acted on (409); a sweep message that
  does is not run. The read API reads a policy and a history only under that
  ARN too. Every pattern that validates an ARN, an account id, a record id
  or a request id uses ASCII classes with `re.ASCII` and is applied with
  `fullmatch`: `\d` also matches digits of other scripts, and `$` also
  matches before a final line feed.
- **Audit.** Same table and discipline as registrations, under
  `pk = CONTAINMENT#<Runtime ARN>`: the history belongs to the Runtime the
  request resolved to, not to the id the caller used, so the two-person rule
  holds whichever id a request uses. An intent event is written before
  anything is changed and a result event says what was and was not done. A
  repeated contain is recorded as `unchanged` and does not replace the
  holder; a contain that failed after the statement may have been written
  still names a holder.
- **Who writes into a Runtime's history.** Only a caller who has a part in
  the Runtime: the role for the action and the Runtime's tenant, for a
  Runtime of a cell that has a containment role. So the history holds every
  contain and release that was allowed, every failure, and the two-person
  refusal (`CON-03-N`), which is written once per person and containment
  and logged after that. Every other refusal goes to the function's log
  with the `request_id` the answer carries, and nothing is read of the
  history for it: a refusal for the role, for the tenant (`CON-04-N`,
  `CON-05-N`), and for a cell that did not enable containment. A history is
  append-only and is never shortened. If those refusals were written, a
  responder of one tenant could fill the history of another tenant's
  Runtime, or a history under an ARN of their own choosing, one event per
  request.
- **How far a read of the history goes.** A contain never reads it, so an
  emergency action does not depend on its length. A release reads it back
  from the newest event to the one that settles who holds the containment
  (`read_holder` in `portal_api/aws/audit.py`), and at most 2000 events. If
  nothing settles it within that, the release is refused with 409 and the
  Runtime stays contained: an unknown holder must not read as no holder.
  The view and the evidence document read the same way and show the newest
  200 events, with `events_truncated` when there are older ones.
- **Who reads the incident record.** `GET /agents/{id}/containment` returns
  who contained the agent, why, and the events only to a role that can
  contain or release. Other roles get the state.
- **Not atomic.** The policy is read, changed and written without a lock.
  Another tool changing the same policy at the same moment could be overwritten.

## CloudWatch Omni hand-off

Nothing from Omni is embedded. Where a cell configures `omniDomainUrl`, the
agents of that cell, its row in `/fleet/health` and `/fleet/summary` carry
`omni_url` so the front end can link out.

`GET /omni/observed-services?cell=<tenant>/<agent>&hours=24` lists the agents
the Omni Context Graph observes in telemetry in the portal's own account.

- **Agents only.** The Context Graph holds every service and resource of an
  account (functions, compute, networks). The request filters on the category
  `GEN_AI_AGENT`, and anything else is dropped.
- **Matched against the inventory.** Each row carries the Runtime ARN (the
  node's resource id cut at the endpoint part), `registered`, `detected`,
  `matched_agent_id` and `inventory_state`. An agent that nobody registered and
  no source detected has `inventory_state: "observed_only"`: it is visible in
  telemetry only.
- **Where it was observed.** An Omni domain sees the Region it lives in, which
  can differ from the cells' Region. The response lists the domains it read
  (`domains`: account alias, Region, URL), and each row carries `omni_region`
  and `account_alias`.
- **Times.** A node known from configuration only reports the epoch as its
  observation time; that is returned as null.
- **Access.** The graph is read with the function's own role in the cell's
  `omniRegion`. A same-account call needs only `cloudwatch:GetContextGraph`;
  no Omni access grant is involved. Cells in other accounts are skipped with a
  warning. Without `cell`, every cell in the portal's own account is covered.

## Lifecycle after approval

What happens to a registration once it is approved: it can be retired, its
periodic review can be attested, and everything the portal knows about its
agent can be downloaded as one document. Specified for the front end in
[ACTIONS_CONTRACT.md](ACTIONS_CONTRACT.md).

- **Rules.** `portal_api/actions/lifecycle_rules.py` and
  `portal_api/reviews.py` are pure functions with no AWS call. Every refusal
  carries a rule identifier (`RET-01-N` to `RET-04-N`, `REV-01-N` to
  `REV-06-N`) and is answered with the status the rule names. It is written
  to the audit trail when the caller has a part in the record, like every
  other refusal (see "Registration and approval").
- **Retire.** `POST /registrations/{record_id}/retire` on the approver
  function sets the record's status to `DEPRECATED` with
  `UpdateRegistryRecordStatus` and waits until the record has settled. It
  needs the approver authority and the record's tenant, and has no two-person
  rule. It is allowed from every settled status; a record that is still being
  created or updated after the wait is refused (`RET-04-N`). Retiring a
  retired record answers `unchanged` and calls nothing. The registry never
  leaves `DEPRECATED`, so
  the functions refuse to approve, reject, update or submit a retired record
  themselves (`RET-03-N`, 409) instead of passing on a service error. A
  retired record can still be deleted.
- **What retire does not do.** It removes nothing that is deployed. A Runtime
  stays until its pipeline removes it, and until then the agent carries the
  risk reason `REGISTRATION_DEPRECATED`.
- **Review attestation.** `POST /registrations/{record_id}/review` on the
  approver function records that an approver reviewed an `APPROVED`
  registration and by when it must be reviewed again (after today in UTC, at
  most 366 days ahead). It never touches the record, because any update of a
  record returns it to `DRAFT`. It writes the usual `intent` and `result`
  events to the record's own partition, and between them one item to the
  partition `pk = REVIEWS`, `sk = EVENT#<UTC timestamp>#<record id>`, with the
  record id, who reviewed, when, the next review date and the reason. Like
  every event it is written with `attribute_not_exists(pk)`: a new item per
  attestation, never an overwrite. The `result` event names the attestation's
  time (`attested_at`).
- **Who attests, and how often.** A review is a second pair of eyes, so the
  record's submitter cannot attest it (`REV-05-N`), as the submitter cannot
  approve it. A record the portal knows no submitter of (published by a
  pipeline) can be attested by any approver of its tenant. And a record's
  review is attested once in 24 hours (`REV-06-N`, 409): every attestation
  lives in the one `REVIEWS` partition, whose read is bounded, so one record
  attested thousands of times would push other records' attestations out of
  that read. An approval is not a review attestation and is not counted.
  Both rules are read from the record's own history, back to its latest
  submit and 24 hours, and each refusal is written once and logged after
  that.
- **An approval counts as a review.** When an approval completes and the
  approved document names `reviewBy`, the approver function also writes an
  attestation of kind `approval` for the record, with that date, or with the
  approval date plus 366 days when the document names a later one, and the
  approver as the reviewer.
  A document with no `reviewBy` writes nothing. The write follows the
  registry's answer, which cannot be taken back, so if it fails the approval
  stands, the result event says that the review date was not recorded, and
  the response has `audit_complete: false`.
- **The effective review date.** One rule: the latest attestation wins, of
  either kind. After an approval the date is the document's own; a later
  review moves it; a later re-approval with a new date moves it again; a
  re-approval of a document with no date leaves the earlier one. A
  registration with no attestation (one approved outside the portal) shows
  the `reviewBy` of its document. `review_by` on an agent,
  `flags.review_overdue` and the `REVIEW_OVERDUE` rule use that date, and the
  agent carries `last_reviewed_at` and `last_reviewed_by`. An attestation for
  a record that no longer exists is ignored. A retired registration is never
  overdue: it can no longer be attested, so the flag would ask for something
  nobody can do.
- **How the read API reads attestations.** With one query of the `REVIEWS`
  partition per inventory load, newest first, never one per agent. The read is
  bounded to 20 pages of 1 MB. If it cannot be read, each agent keeps its
  registration's own date and `/fleet/summary` says so in `warnings` and
  `review_attestations`; the inventory never fails for it.
  `GET /registrations/{record_id}` takes the last review from the record's own
  events, so it shows an attestation as soon as it is made.

### Evidence document

`GET /agents/{id}/evidence` returns one JSON document about one agent as a
download (`agent-evidence-<agent name>-<UTC date>.json`, `Cache-Control:
no-store`). Any mapped role may read it. Its sections:

| Section | Holds | From |
| --- | --- | --- |
| `generated_at`, `generated_by`, `portal_environment` | When, the caller's label and role, `PORTAL_ENV` | The request |
| `agent` | Id, name, tenant, environment, account alias or masked account, Region, Runtime ARN, inventory state, detection sources, reader status, inbound authorizer | The inventory |
| `registration` | Record id and name, status, version, the governance document exactly as stored, and its SHA-256 (the value the audit events carry). Null for an agent with no registration | The inventory |
| `decisions` | The registration's audit events, oldest first | The audit table, read for the document |
| `reviews` | The attestations of both kinds, oldest first, and the effective review date with its source | The inventory |
| `containment` | The current state, who holds it, the background sweeps (scheduled, done, and since when no session the portal can find is running), the containment events, oldest first, and how long a contain and a release take to apply everywhere | The Runtime's resource policy through the cell reader, the audit table, and `portal_api/containment_timing.py` |
| `risk` | Level, reasons, flags and `assessed_at` | The inventory |
| `policy` | Per linked Tool Gateway: id, name, policy mode, number of policies, and SHA-256 hashes of the Cedar statements as deployed | The gateway's policy engine through the cell reader |
| `release` | The latest execution of the cell's Workload pipeline: id, status, evaluation gate result, times. Null when the cell names no pipeline | CodePipeline |
| `limitations` | What could not be read and why | Collected while the document is made |

- **Never fails on a missing part.** Every section is always present. A part
  that cannot be read is left empty or null and named in `limitations`.
- **One moment, and no contradiction.** The agent, registration, reviews and
  risk sections come from one inventory, which describes the moment
  `risk.assessed_at` (to the microsecond, taken before anything is read for
  it, with the registry read afresh). The events are read when the document
  is made. If one of them is newer than that moment (a decision taken a
  moment ago, while the inventory in the cache is from before it), the
  inventory is loaded again once, past the cache, and the document is built
  from that: it never lists an approval and still calls the registration
  pending. The fresh inventory then serves the next requests from the cache.
  Only an event that can change what those sections show counts: the result
  of a decision that was carried out (`allowed` or `unchanged`). A refusal, a
  failure, an intent and a background sweep change nothing there, so they
  cause no load and no note. And because the load reads every cell, it
  happens for a document at most once in 15 seconds per execution
  environment, a limit the document shares with the page of one agent
  (`GET /agents/{agent_id}`, see "How fresh a read is"). When it is not done
  for that reason, or fails, the sections
  stay as they were and `limitations` says that the action is listed but not
  yet reflected.
- **The incident record follows the caller's role.** Every mapped role may
  download the document, but who contained the agent, why, and the
  containment events are included only for a role that can contain or release
  (`security`, `platform`, `sre`), the same rule as the containment view. For
  anyone else the section keeps the state, when it began and the delays, and
  `limitations` says that the incident record is limited to those roles. The
  events are read under the Runtime's key, like the view.
- **Containment is not instant.** The state is what the Runtime's resource
  policy says, and the service applies a change to it host by host. The
  section states both measured delays (`enforcement_delay_seconds` for a
  contain, `release_delay_seconds` for a release) and says them in a sentence,
  so a reader can set them against the times of the containment events.
- **Hashes, not policy text.** `cedar_sha256` is the SHA-256 of a gateway's
  Cedar statements in ascending policy id order, each followed by a newline,
  and every policy has its own hash. The text is not included.
- **What it never holds.** No value of a Runtime environment variable (only
  facts derived from the names, such as the inbound authorizer), no external
  id, no token, no role ARN, and no account id outside an ARN.
- **Pure assembly.** `portal_api/evidence.py` builds the document from an
  inventory entry and the events fetched for it, with no AWS call and no
  clock, so it is tested without AWS.

## Registration and approval

The two action functions and their endpoints are specified in
[ACTIONS_CONTRACT.md](ACTIONS_CONTRACT.md). In short:

- **Who decides.** `portal_api/registration_core.py` is a rule-for-rule port
  of the TypeScript authorization core in
  `packages/agent-registry/src/agent-registration-api.ts`. Both run the shared
  vectors in `packages/agent-registry/vectors/registration-decisions.json`.
  `portal_api/actions/authority.py` only translates the portal's facts into
  the core's terms: `platform` is registrar and approver for every tenant,
  `developer` is registrar for its own tenants, `approver` and `security` are
  approvers for their tenants.
- **Record shape.** The same document, record name and calls as
  `pipelines/publish_agent_record.py`. `schemas/agent-governance-1.0.json` is a
  copy of the canonical schema in `packages/agent-registry/schemas`.
- **Audit trail.** Every decision about a record is appended to the Amazon
  DynamoDB table in `PORTAL_AUDIT_TABLE` (`pk = RECORD#<record_id>`,
  `sk = EVENT#<UTC timestamp>#<uuid>`). For an allowed action an `intent` event
  is written first; if that write fails the action is not performed. A
  `result` event follows the registry call. Events are written with
  `attribute_not_exists(pk)` and never updated or deleted. The `result` event
  of an approval also stores the approved document (attribute `document`), so
  a later change can be shown against it.
- **Who writes into a record's history.** Only a caller who has a part in
  the record: the authority the action needs, and the record's tenant
  (`has_part` in `portal_api/actions/authority.py`). `ActionEngine.deny` is
  the one place a refusal is written, and it checks that itself, whatever the
  flow that called it. Every other refusal goes to the function's log with a
  `request_id`, which the 403 also carries:
  - a caller without the needed authority, refused before the record is read;
  - a caller who holds the authority but not the record's tenant
    (`cross-tenant ... is denied`, `RET-02-N`, `REV-02-N`);
  - a create refused for authority, for the tenant or by `REG-13-N`, before
    any record exists.

  A history is keyed by a record the function has read, never by an id or a
  name a caller sent, and it is never shortened. Otherwise any signed-in user
  could fill the history of another tenant's record, or of a name that does
  not exist.
- **How far a read of a history goes.** No read follows a history to its
  end without a bound (`portal_api/aws/audit.py`). The approver function
  reads a record's history back from its newest event to its latest submit,
  and at most 2000 events; if the submit is not among them the decision is
  refused with 409, because an unknown submitter must not read as none. The
  history endpoint and the evidence document show the newest 200 events and
  say when there are older ones (`events_truncated`, `decisions_truncated`).
  The registration detail reads the newest 2000 and, for who created the
  record, its oldest five.
- **References.** `portal_api/actions/reference_rules.py` (pure): a
  registration's Runtime, Tool Gateway and policy engine must run in a cell
  of the registration's own tenant, or in an account and Region where the
  portal has no cell (`REG-13-N`). The registrar function checks it on create
  and update and the approver function again on approve, from `PORTAL_CELLS`
  alone: no call is made and no permission is needed. Without it a registrar
  of one tenant could register another tenant's Runtime, and the inventory
  would show that Runtime under the wrong tenant, owner and risk class. In an
  account and Region that several tenants share, the place does not say
  whose a Runtime is, so a reference there also needs the caller to hold
  every tenant hosted there: the registrar on create and update, the
  approver on approve. The `platform` role holds every tenant.
- **A registration's own review date.** `review_by` may be at most 366 days
  ahead when a registration is created or updated (422). An approval records
  the document's date, or the approval date plus 366 days if the document
  names a later one (a record written before this rule, or by other means).
  So no date gets further than a year ahead by any way in
  (`portal_api/reviews.py`): a registration approved with a date in the far
  future would otherwise never be due.
- **Separation of duties.** The submitter of a record is the actor of its
  latest allowed `submit` event, read from the audit table with a strongly
  consistent query. The submitter cannot approve or reject the record.
- **Fail closed.** A function whose `PORTAL_ACTION_ROLE` does not match its
  handler answers 404 for everything. Each function answers 404 for the other
  functions' routes. The sweeper, which serves no route, raises before it
  reads a message when its `PORTAL_ACTION_ROLE` is not `sweeper`.

## Identity

The API runs behind an Amazon API Gateway HTTP API with a JWT authorizer, which
validates signature, issuer and audience before a function is invoked.
`PORTAL_IDENTITY_PROVIDER` selects how the claims are read:

- `cognito`: subject `sub`, groups from the union of `cognito:groups` and
  `custom:groups` (the claim a SAML workforce identity provider's groups are
  mapped to; a comma-separated or JSON array string). The API receives the
  Cognito ID token.
- `entra`: subject `oid`, app roles from `roles`, groups from `groups`.

`PORTAL_GROUP_ROLE_MAP` maps a group or app role name to one of `platform`,
`security`, `sre`, `approver`, `finops`, `developer`, `readonly`. The highest
mapped role wins. No identity is `401`; no mapped group is `403`.

**The read API takes the caller from the claims API Gateway verified** and
passes in the event.

**The three action functions verify the token themselves**
(`portal_api/identity/verify.py`) and build the caller from the token alone.
They do not read the claims in the event, so an event made up by someone who
can invoke a function directly carries no weight: without a token the issuer
signed, the answer is `401`. For each request they check:

1. **The token:** `Authorization: Bearer <token>`.
2. **Algorithm:** `RS256` only. `none` and the HMAC algorithms are refused
   before any key is looked up.
3. **Key and signature:** the token's key id names a key of the issuer's
   published key set, and the signature verifies against it.
4. **Issuer:** `iss` equals `PORTAL_JWT_ISSUER` exactly.
5. **Audience:** one of `PORTAL_JWT_AUDIENCE`, in `aud` for an ID token and
   for Entra, in `client_id` for a Cognito access token.
6. **Kind of token (Cognito):** `token_use` equals `PORTAL_JWT_TOKEN_USE`
   (`id` by default, which is what the portal sends).
7. **Time:** `exp` in the future, `iat` and `nbf` not in the future, with 60
   seconds of leeway. `exp`, `iat`, `iss` and the subject claim must be there.
8. **A person's token (Entra):** an app-only token is refused. The portal's
   rules are about people, and an application can get a token for the
   portal's audience with its own credentials; with an app role mapped to a
   portal role it would otherwise pass as a person. It is recognised by
   `idtyp` being `app`, or by being an access token (it carries `azp`,
   `azpacr`, `appid`, `appidacr` or `scp`) with no scope in `scp`. An ID
   token carries none of those claims and is accepted.

A token that fails any check is answered with `401` and the usual body; the
reason goes to the function's log, never to the caller, and the token is
never logged. The library is PyJWT with `cryptography`, both pinned in
`requirements.txt`.

**The issuer's keys** are read over HTTPS from
`<issuer>/.well-known/jwks.json` for Cognito, and from `PORTAL_JWKS_URL` for
Entra, so no discovery call is made. That is the functions' only request
outside AWS APIs; it needs outbound HTTPS and no IAM permission, and a
redirect is not followed. The keys are kept in the execution environment for
12 hours. A key id that is not among them triggers one refresh, and there is
at most one refresh every 5 minutes, so a token with an invented key id cannot
make a function fetch on every request. A refresh that fails keeps the keys
already there, but not for ever: keys fetched more than 48 hours ago are not
used, so a key the issuer withdrew is not trusted for as long as the issuer
cannot be reached. If no key can be had at all, or only keys that old, the
answer is `503` and nothing is done.

**The address of the keys is not free to choose.** Whoever signs with a key
published at that address is believed, so a wrong host there would make its
owner a signer of portal tokens. The address follows from the issuer:

- Cognito: always `<issuer>/.well-known/jwks.json`. `PORTAL_JWKS_URL` is not
  used, and setting it to any other address is a configuration error.
- Entra: the issuer must be `https://login.microsoftonline.com/<tenant id>/v2.0`
  or `https://sts.windows.net/<tenant id>/`, and `PORTAL_JWKS_URL` must be
  `https://login.microsoftonline.com/<that tenant id>/discovery/v2.0/keys`.
  The hosts it may name are in one constant, `ENTRA_KEY_HOSTS` in
  `portal_api/config.py`; a national cloud is added there.

**What this does not cover.**

- **The read API** still trusts the claims API Gateway passes. A principal of
  the Platform account who holds `lambda:InvokeFunction` on the read function
  can call it with claims of its own making and read what any persona may
  read. It cannot change anything that way. Treat that permission on the
  portal's functions as a protected authority of the Platform account.
- **The sweeper** has no caller and no token: its input is a queue message,
  which is not signed. Only the containment function's role can put a
  message on its queue, but whoever holds `lambda:InvokeFunction` on the
  sweeper can hand it one directly. That can start a sweep that a contain on
  record scheduled, when that sweep is due and has not run: the sweep the
  queue would have started. Nothing more: no sweep under a request id of the
  sender's own, none twice, none early, none of a Runtime the portal's
  statement does not contain at that moment, and no event for a message
  that is not valid. The sweeper finds the cell and its role in its own
  configuration, reads the Runtime's history and then its policy.
- **Revocation.** A token is accepted until it expires, as with the
  authorizer.

**Who a person is, and what a record shows beside it.** The subject is the
identity: the token's `sub` for Cognito and `oid` for Entra. Every rule that
compares people compares subjects (the two-person rule, separation of duties
on approve and on review), and every record stores the subject
(`actor_subject`, `contained_by`, `reviewed_by`). Nothing is decided on
anything else.

Beside the subject a record carries a label, for a person to read
(`Principal.label` in `portal_api/identity/provider.py`). It is the actor's
label on an audit event, the reviewer's on an attestation and the author's on
an evidence document:

- Cognito, a local user: the `email` when `email_verified` is true; otherwise
  the subject.
- Cognito, a federated user (the token has an `identities` claim): the
  `email`, which the identity provider set; otherwise the subject.
- Entra: `preferred_username`, as the directory holds it; else `upn`; else
  the subject.

The label is a reading aid, not an identity. It can change for the same
person: a local Cognito user can replace their email and verify the new one,
and a directory can rename a user (for an Entra guest it is the guest's own
address). Two events of one person can therefore carry different labels;
their subject is the same. The `name` claim changes more freely still and is
never used for a record. `GET /users/me` returns it in `name`, for showing
callers their own name.

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `PORTAL_ENV` | yes | `nonprod` or `prod` |
| `PORTAL_REGISTRY_ID` | yes | Id of the platform Agent Registry (tool records; also agent records unless the next variable is set) |
| `PORTAL_DISCOVERY_REGISTRY_ID` | no | Id of the organization-scoped discovery registry (AWS Agent Registry auto-detection), in the same Region. Adds `organization_registry` as a detection source |
| `PORTAL_OWNER_GROUPS` | no | The owner roster: a JSON list of the owner groups that exist. An agent whose `owner_group` is not in it is flagged `ownerless` (reason `OWNER_GROUP_NOT_IN_ROSTER`). Unset means the roster is unknown and that rule never applies |
| `PORTAL_INACTIVE_DAYS` | no | Days without an invocation after which an agent is flagged `inactive`. Default `30`, 1 to 365 |
| `PORTAL_AGENT_REGISTRY_ID` | no | Id of a separate registry, in the same Region, that holds the agent governance records. Use it when the platform registry auto-approves, so that agent records wait for a person |
| `PORTAL_REGISTRY_REGION` | yes | Region of the registry. Also used for the other platform-account reads (pipelines, guardrails) |
| `PORTAL_CELLS` | yes | JSON list of `{ tenantId, agentId, applicationId?, environment, accountId, region, readerRoleArn, externalId?, alarmNamePrefix?, pipelineName?, accountAlias?, containmentRoleArn?, containmentSpans?, omniDomainUrl?, omniRegion? }`. `containmentSpans` (true or false, default false) lets containment also search the cell's spans for sessions; it needs a containment role and widens what that role can read (see "Containment") |
| `PORTAL_IDENTITY_PROVIDER` | yes | `cognito` or `entra` |
| `PORTAL_GROUP_ROLE_MAP` | yes | JSON object, group or app role name to portal role |
| `PORTAL_GUARDRAIL_TAG_KEY`, `PORTAL_GUARDRAIL_TAG_VALUE` | no | Tag that marks a guardrail as part of the blueprint. Both empty (the default): every guardrail in the account and Region is listed and tags are not read. Set both or neither |
| `PORTAL_MODEL_ALLOWLIST` | yes | JSON list of model ids, or of `{ modelId, provider?, regions?, status? }` |
| `PORTAL_ALLOWED_ORIGINS` | no | JSON list of origins for CORS. Default: none. `*` is rejected |
| `PORTAL_CACHE_TTL_SECONDS` | no | In-process cache lifetime for list reads. Default `30`, `0` disables |
| `PORTAL_LOG_LEVEL` | no | Default `INFO` |
| `PORTAL_AUDIT_TABLE` | for history | Audit table name. Without it `/registrations/{record_id}/history` answers 500, `/registrations/{record_id}` omits the people fields, review attestations are not read (every review date is the registration's own), and the evidence document has no events |
| `PORTAL_GROUP_TENANT_MAP` | no | Lets `/users/me` report `registration_tenants` |
| `PORTAL_DEV_AUTH` | no | Local development only, see below |

The action functions read a smaller set, all required unless noted:

| Variable | Meaning |
| --- | --- |
| `PORTAL_ACTION_ROLE` | `registrar`, `approver` or `containment`; must match the handler |
| `PORTAL_CELLS` | The cells, as above. The containment function acts in them (`containmentRoleArn` and `externalId` on those that opt in). The registrar and approver functions only read which tenant runs where, for the rule about a registration's references; they assume no role |
| `PORTAL_SWEEP_QUEUE_URL` | Containment function only, optional: the URL of the sweep queue. Unset or empty: no background sweeps, and a contain is exactly what it is without them. A value that is not an Amazon SQS queue URL does not stop the function, unlike every other malformed setting: contain and release still work, the `background` step of each contain is `failed` and names the setting, the result is partial, and the function logs it at error level |
| `PORTAL_ENV`, `PORTAL_REGISTRY_ID`, `PORTAL_REGISTRY_REGION` | As above, except that `PORTAL_REGISTRY_ID` here is the registry that holds the agent records (the agent registry when there are two). The audit table is read in the registry's Region |
| `PORTAL_IDENTITY_PROVIDER`, `PORTAL_GROUP_ROLE_MAP` | As above |
| `PORTAL_JWT_ISSUER` | The token issuer, exactly as it stands in the token's `iss`. For Cognito, `https://cognito-idp.<region>.amazonaws.com/<user pool id>`. For Entra, `https://login.microsoftonline.com/<tenant id>/v2.0` or `https://sts.windows.net/<tenant id>/` |
| `PORTAL_JWT_AUDIENCE` | JSON list of the accepted app client ids or audiences. The same values the API Gateway authorizer has |
| `PORTAL_JWT_TOKEN_USE` | Optional, Cognito only: `id` (default) or `access` |
| `PORTAL_JWKS_URL` | Entra only, and required there: the key set of the issuer's own tenant, `https://login.microsoftonline.com/<tenant id>/discovery/v2.0/keys`. Any other address is a configuration error. Not used for Cognito, where the address is always derived from the issuer; setting it to anything else is a configuration error too |
| `PORTAL_GROUP_TENANT_MAP` | JSON object, group or app role name to a list of tenant ids. `"*"` is allowed only for a group mapped to `platform` |
| `PORTAL_AUDIT_TABLE` | Audit table name |
| `PORTAL_ALLOWED_ORIGINS`, `PORTAL_LOG_LEVEL` | Optional, as above |

The sweeper reads six, all required except the last: `PORTAL_ACTION_ROLE`
(`sweeper`), `PORTAL_ENV`, `PORTAL_REGISTRY_REGION` (the Region of the audit
table), `PORTAL_CELLS` (the same value as the containment function's),
`PORTAL_AUDIT_TABLE` and `PORTAL_LOG_LEVEL`. It serves no caller, so it has
no identity settings and reads no registry.

If a required value is missing or malformed, every data endpoint answers `500`
with a reason that names the variable, and the reason is logged. There is no
fallback to sample data. The sweeper raises instead, so its message goes back
to the queue and ends in the dead-letter queue.

The token variables are required for the three action functions, so the code
that reads them and the variables must be deployed together: an action
function without `PORTAL_JWT_ISSUER` answers `500` with "PORTAL_JWT_ISSUER is
not set: the action functions verify the caller's token themselves and need
the token issuer". The read API and the sweeper do not read them.

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
export PORTAL_DEV_AUTH=1   # plus the variables above
.venv/bin/uvicorn handler:app --port 8000
curl -H 'x-portal-dev-user: dev@example.com' -H 'x-portal-dev-groups: my-group' \
  http://localhost:8000/api/v1/users/me
```

`PORTAL_DEV_AUTH=1` lets a request name its user and groups in headers. The
role is still resolved through `PORTAL_GROUP_ROLE_MAP`. It is ignored whenever
`AWS_LAMBDA_FUNCTION_NAME` is set, so it cannot be enabled inside AWS Lambda.
With it on, and none of the token variables set, an action function run
locally needs no issuer.
Local runs use your own AWS credentials for the platform account and still
assume each cell's reader role.

## Build

```bash
./build.sh
```

Produces `dist/` for arm64, Python 3.13 Lambda functions, with `handler.py`,
`registrar_handler.py`, `approver_handler.py`, `containment_handler.py` and
`sweep_handler.py` at its root. Zip the contents of `dist/`. boto3 and botocore are bundled
at pinned versions on purpose: the Agent Registry control-plane client is newer
than the SDK included in the Lambda runtime.

Function settings used by the infrastructure: Python 3.13 on arm64, timeout 29 seconds, memory 1024 MB. The source stays compatible with Python 3.12.

The sweeper differs: timeout 900 seconds, invoked by the sweep queue one
message at a time (batch size 1). The queue's visibility timeout must be at
least the function's timeout, and a message that fails twice goes to a
dead-letter queue. A sweep keeps the last 30 seconds of its time to write its
audit event. A message whose sweep was claimed and never left its event (the
run was cut short) fails each time it is delivered, so it ends in the
dead-letter queue as well. The construct also keeps a message for four
hours, lets only the containment function's role send, receive, delete,
change the visibility of or purge a message, and raises two alarms: one for
a message in the dead-letter queue, one when the oldest message has waited
for more than an hour. The sweeper reads the audit table as well as writing
to it, so its role needs `dynamodb:Query` beside `dynamodb:PutItem`, both
under the leading key `CONTAINMENT#*`. Contain and release each have a
request budget of their own at the API (5 requests per second, burst 10).

## Test

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check .
```

Tests use botocore `Stubber` and hand-written fakes. They never call AWS.

## Licence

MIT-0, except `portal_api/models/wire.py`, which is derived from an
Apache-2.0 project and carries its own header.
