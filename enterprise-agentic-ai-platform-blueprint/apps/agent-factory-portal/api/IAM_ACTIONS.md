# IAM actions used by the Agent Factory Portal API

This file lists every IAM action the code calls, per role, and nothing else.
`tests/test_readonly.py` fails if a role's code calls an operation that is not
in its table, or if a table lists an action that role's code does not call.

There are five Lambda functions. Four have their own role; the sweeper runs
under the containment function's role. Each cell account has a reader role
and, where the cell opts in, a containment role:

| Function | Handler | Role | Can change |
| --- | --- | --- | --- |
| Read API | `handler.handler` | read role | Nothing |
| Registrar | `registrar_handler.handler` | registrar role | Registry records (create, update, submit, delete); appends audit events |
| Approver | `approver_handler.handler` | approver role | A registry record's status (approve, reject, retire); appends audit events, and keeps the latest review attestation of a record |
| Containment | `containment_handler.handler` | containment function role, and each opted-in cell's containment role | One deny statement in a Runtime's resource policy; stops Runtime sessions; appends audit events; sends sweep messages |
| Sweeper | `sweep_handler.handler` | the containment function role, and each opted-in cell's containment role | Stops the sessions of a Runtime that is contained; appends audit events. It serves no route |

The read API has no code path that creates, updates, deletes, tags or invokes
anything, and it does not import the action code at all.

**Role session names.** Each function that assumes a role in a cell does so
under a session name of its own, which is the last part of the caller's ARN
in every CloudTrail event of the cell account that it causes:

| Function | Role it assumes in a cell | Role session name |
| --- | --- | --- |
| Read API | the cell's reader role | `portal-reader` |
| Containment | the cell's containment role | `portal-containment` |
| Sweeper | the cell's containment role, with a session policy (section 7) | `portal-sweeper` |

So a `PutResourcePolicy` on a Runtime by a session named `portal-sweeper`
cannot occur (its session policy leaves that action out), and an alarm in
the cell on any policy write that is not by `portal-containment` says more
than one on the role alone.

Placeholders: `PLATFORM` is the platform account id, `CELL` is a cell account
id, `REGION` is the Region of the resource, `AUDIT_TABLE` is the table named in
`PORTAL_AUDIT_TABLE`.

## 1. Read role (platform account)

Region for every platform-account call is `PORTAL_REGISTRY_REGION`.

| Action | Resource it can be narrowed to | Needed by |
| --- | --- | --- |
| `sts:AssumeRole` | The `readerRoleArn` of each entry in `PORTAL_CELLS` (exact role ARNs, no wildcard) | Every endpoint that reads a cell: `/agents*`, `/mcp-servers*`, `/governance-graph`, `/principals/{id}`, `/observability/metrics`, `/fleet/health` |
| `agent-registry:ListRegistryRecords` | `arn:aws:agent-registry:REGION:PLATFORM:registry/<PORTAL_REGISTRY_ID>` and, when set, the registries named in `PORTAL_AGENT_REGISTRY_ID` and `PORTAL_DISCOVERY_REGISTRY_ID` | `/agents*`, `/mcp-servers*`, `/governance-graph`, `/principals/{id}`, `/observability/metrics`, `/catalog/tools`, `/registrations`, `/registrations/{record_id}` |
| `agent-registry:GetRegistryRecord` | `arn:aws:agent-registry:REGION:PLATFORM:registry/<PORTAL_REGISTRY_ID>/record/*` and, when set, the records of the registries named in `PORTAL_AGENT_REGISTRY_ID` and `PORTAL_DISCOVERY_REGISTRY_ID` | Same as `ListRegistryRecords` (the list operation does not return descriptors) |
| `codepipeline:ListPipelineExecutions` | `arn:aws:codepipeline:REGION:PLATFORM:<pipelineName>` for each `pipelineName` in `PORTAL_CELLS` | `/agents/{id}/evals/runs` |
| `codepipeline:ListActionExecutions` | Same pipeline ARNs | `/agents/{id}/evals/runs` (EvaluationGate action result) |
| `dynamodb:Query` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | `/registrations/{record_id}`, `/registrations/{record_id}/history`, `/agents/{id}/containment`, `/agents/{id}/evidence`; also every endpoint that returns agents (`/agents*`, `/agents/export`, `/fleet/summary`, `/governance-graph`): two queries per inventory load read the latest review attestation of every record |
| `cloudwatch:GetContextGraph` | `*`; can be limited to the Omni Region (the cells' `omniRegion`) with an `aws:RequestedRegion` condition | `/omni/observed-services` |
| `bedrock:ListGuardrails` | `*` (list operation) | `/guardrails`, `/guardrails/{id}` |
| `bedrock:ListTagsForResource` | `arn:aws:bedrock:REGION:PLATFORM:guardrail/*` | `/guardrails`, `/guardrails/{id}`. Called only when `PORTAL_GUARDRAIL_TAG_KEY` is set (tag filter); not needed when it is empty |
| `bedrock:GetGuardrail` | `arn:aws:bedrock:REGION:PLATFORM:guardrail/*` | `/guardrails/{id}` |

With `PORTAL_AGENT_REGISTRY_ID` set, the read role needs the two registry
read actions on both registries: tool records (`/catalog/tools`, the tool join
on gateways) are read from `PORTAL_REGISTRY_ID`, and agent governance records
(`/agents*`, `/registrations*`, the governance graph and everything derived
from them) from `PORTAL_AGENT_REGISTRY_ID`. Without it, one registry holds both.

With `PORTAL_DISCOVERY_REGISTRY_ID` set, the read role needs the same two
actions on that registry too. It is read for `/agents*`, `/mcp-servers*`,
`/governance-graph`, `/fleet/summary` and the export: its records name the
Runtimes and Gateways the organization-scoped auto-detection found.
`GetRegistryRecord` is called there only for a detected Runtime that no cell
reader also saw.

`cloudwatch:GetContextGraph` is the CloudWatch Omni Context Graph read (the
SDK client `cloudwatchomni` signs requests with the service name
`cloudwatch`). The action name was verified live with a session policy that
held only this action: the call succeeds, and it is denied without the action
or when the policy pins the action to another Region. A SigV4 call from a
principal of the same account needs no Omni access grant. The call is made
only for cells in the portal's own account, in the cell's `omniRegion`, and
asks for agent nodes only.

The function also needs its own log delivery permissions (the AWS managed
basic execution policy or an equivalent scoped to its log group). That is
infrastructure, not something the code calls.

Endpoints that call no AWS API: `/health`, `/users/me`, `/observability/settings`, `/catalog/models`.

## 2. Cell reader role (each cell account)

Trust: the portal Lambda role only, with an external id condition when the
cell sets `externalId`. Session duration used by the code is 900 seconds.

| Action | Resource it can be narrowed to | Needed by |
| --- | --- | --- |
| `bedrock-agentcore:ListAgentRuntimes` | `*` (list operation) | `/agents*`, `/governance-graph`, `/principals/{id}`, `/observability/metrics`, `/mcp-servers/{id}/grants` |
| `bedrock-agentcore:GetAgentRuntime` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` | Same as `ListAgentRuntimes` (creation time and the configured Tool Gateway URL) |
| `bedrock-agentcore:GetResourcePolicy` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` | Same as `ListAgentRuntimes` (whether the Runtime's resource policy holds the containment statement). Optional: without it `contained` reads as unknown |
| `bedrock-agentcore:ListAgentRuntimeVersions` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` | `/agents/{id}/deployments` |
| `bedrock-agentcore:ListGateways` | `*` (list operation) | `/mcp-servers*`, `/agents*`, `/governance-graph`, `/principals/{id}`, `/observability/metrics` |
| `bedrock-agentcore:GetGateway` | `arn:aws:bedrock-agentcore:REGION:CELL:gateway/*` | Same as `ListGateways` (URL, authorizer type, policy engine configuration) |
| `bedrock-agentcore:ListGatewayTargets` | `arn:aws:bedrock-agentcore:REGION:CELL:gateway/*` | Same as `ListGateways` (tools) |
| `bedrock-agentcore:GetGatewayTarget` | `arn:aws:bedrock-agentcore:REGION:CELL:gateway/*` | Same as `ListGateways` (tool schemas) |
| `bedrock-agentcore:ListTagsForResource` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` and `arn:aws:bedrock-agentcore:REGION:CELL:gateway/*` | Same as `ListAgentRuntimes` and `ListGateways` (tenant, agent and environment tags). Optional: without it, tags read as empty |
| `bedrock-agentcore:ListPolicies` | `arn:aws:bedrock-agentcore:REGION:CELL:policy-engine/*` | `/mcp-servers/{id}/policies` |
| `bedrock-agentcore:GetPolicy` | `arn:aws:bedrock-agentcore:REGION:CELL:policy-engine/*/policy/*` | `/mcp-servers/{id}/policies` (only when the list response omits the Cedar statement) |
| `cloudwatch:DescribeAlarms` | `arn:aws:cloudwatch:REGION:CELL:alarm:*` | `/fleet/health`; also every endpoint that returns agents with their risk (`/agents*`, `/agents/export`, `/fleet/summary`, `/governance-graph`), because the cell's health state is a risk fact |
| `cloudwatch:DescribeAlarmHistory` | `arn:aws:cloudwatch:REGION:CELL:alarm:<alarm name prefix>*` | Same as `DescribeAlarms` (only for alarms whose state changed in the last 24 hours) |
| `cloudwatch:GetMetricData` | `*` (no resource-level permissions) | `/agents/{id}/metrics`, `/observability/metrics`; also every endpoint that returns agents (the `inactive` flag: one request per cell account covers all of its Runtimes) |
| `logs:StartQuery` | `arn:aws:logs:REGION:CELL:log-group:aws/spans:*` | `/agents/{id}/traces`, `/agents/{id}/metrics`, `/observability/metrics` |
| `logs:GetQueryResults` | `*` (no resource-level permissions) | `/agents/{id}/traces`, `/agents/{id}/metrics`, `/observability/metrics` |

Notes for the policy author:

- `logs:StartQuery` starts a read-only CloudWatch Logs Insights query. It is
  the only action here whose name does not begin with List, Get or Describe.
- The alarm name prefix of a cell is `alarmNamePrefix` when set, otherwise
  `agenticai-<environment>-<tenantId>-<agentId>`.
- `cloudwatch:DescribeAlarms` is called with `AlarmNamePrefix`. Whether it can
  be narrowed below all alarms in the account and Region for a prefix call was
  not verified, so the table gives the account-wide alarm ARN.
- The IAM service prefix `agent-registry` is taken from the SDK signing name
  and the registry ARN format. Confirm it against the Service Authorization
  Reference when writing the policy.
- If the `aws/spans` log group is encrypted with a customer managed AWS KMS
  key, the reader role also needs decrypt permission on that key. The code does not
  call AWS KMS itself.

## 3. Registrar role (platform account)

Function `registrar_handler.handler`, `PORTAL_ACTION_ROLE=registrar`. Its `PORTAL_REGISTRY_ID` is the
registry that holds the agent records (the agent registry when there are two).

| Action | Resource it can be narrowed to | Needed by |
| --- | --- | --- |
| `agent-registry:ListRegistryRecords` | `arn:aws:agent-registry:REGION:PLATFORM:registry/<PORTAL_REGISTRY_ID>` | `POST /registrations` (the registry does not enforce unique record names, so the function looks for an existing record of the same name) |
| `agent-registry:GetRegistryRecord` | `arn:aws:agent-registry:REGION:PLATFORM:registry/<PORTAL_REGISTRY_ID>/record/*` | Every registrar route (current record, and waiting for CREATING or UPDATING to settle) |
| `agent-registry:CreateRegistryRecord` | The registry ARN | `POST /registrations` |
| `agent-registry:UpdateRegistryRecord` | The registry's record ARNs | `PUT /registrations/{record_id}` |
| `agent-registry:SubmitRegistryRecordForApproval` | The registry's record ARNs | `POST /registrations/{record_id}/submit` |
| `agent-registry:DeleteRegistryRecord` | The registry's record ARNs | `DELETE /registrations/{record_id}` |
| `dynamodb:PutItem` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | Every registrar route (audit events) |

The registrar code does not call `Query` on the audit table. Granting it is
harmless but not needed.

## 4. Approver role (platform account)

Function `approver_handler.handler`, `PORTAL_ACTION_ROLE=approver`. Its `PORTAL_REGISTRY_ID` is the
registry that holds the agent records.

| Action | Resource it can be narrowed to | Needed by |
| --- | --- | --- |
| `agent-registry:GetRegistryRecord` | The registry's record ARNs | `POST /registrations/{record_id}/approve`, `POST /registrations/{record_id}/reject`, `POST /registrations/{record_id}/retire`, `POST /registrations/{record_id}/review` |
| `agent-registry:UpdateRegistryRecordStatus` | The registry's record ARNs | Approve, reject and retire. Review does not call it: it changes no record |
| `dynamodb:Query` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | Approve, reject and review (who submitted the record, and for a review when it was last attested; strongly consistent read). Retire does not query |
| `dynamodb:PutItem` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | All four routes (audit events). A review and every approval also write the record's latest attestation: the one item `REVIEWS` / `RECORD#<record id>` |

Neither action role has `dynamodb:UpdateItem` or `dynamodb:DeleteItem`, and the
code writes every event, mark and claim with the condition
`attribute_not_exists(pk)`, so an audit event can be added but never changed
or removed through the API. One item is not an event and is the only one a
later `PutItem` may replace: the latest review attestation of a record
(`pk = REVIEWS`, `sk = RECORD#<record id>`), which the approver function
writes with the condition `attribute_not_exists(#at) OR #at < :at`, so that
only an attestation that was attested later takes its place. The attestation
itself stays in the record's history, as the result event that names it. IAM
cannot tell the two conditions apart: `dynamodb:PutItem` allows both, and
which one a write carries is the code's (`portal_api/actions/audit_writer.py`,
the only module that writes to the table). The approver role
cannot create, update or delete a record; the registrar role cannot set a
record's status.

## 5. Containment function role (platform account)

Function `containment_handler.handler`, `PORTAL_ACTION_ROLE=containment`.

| Action | Resource it can be narrowed to | Needed by |
| --- | --- | --- |
| `sts:AssumeRole` | The `containmentRoleArn` of each cell that opts in (exact role ARNs) | Both containment routes. Everything in the cell is done with that role |
| `agent-registry:GetRegistryRecord` | The records of the registry that holds the agent records (this function's `PORTAL_REGISTRY_ID`) | Both routes, for a registered agent: its Runtime ARN is read from its record, never taken from the request. The record plays no part in deciding the tenant |
| `dynamodb:Query` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | Both routes (who contained the agent, for the two-person rule; strongly consistent read) |
| `dynamodb:PutItem` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | Both routes (audit events, and the mark that records a refused release once) |
| `sqs:SendMessage` | The ARN of the sweep queue (the queue named in `PORTAL_SWEEP_QUEUE_URL`) | Contain, when a sweep queue is configured: the messages for the background sweeps. Not needed when the variable is unset |

This role can read a record of that one registry and nothing more of it: it
cannot list records, cannot change any record's content or status, cannot
assume a cell's reader role, and has no `bedrock-agentcore` permission of its
own.

## 6. Cell containment role (each cell that opts in)

Trust: the containment function's role only, with the cell's external id.

| Action | Resource it can be narrowed to | Needed by |
| --- | --- | --- |
| `bedrock-agentcore:GetResourcePolicy` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` | Contain and release (read before the change, and again to verify) |
| `bedrock-agentcore:PutResourcePolicy` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` | Contain (add the deny statement); release when other statements remain |
| `bedrock-agentcore:DeleteResourcePolicy` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` | Release, only when the containment statement was the policy's only statement |
| `bedrock-agentcore:StopRuntimeSession` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` | Contain (stop the Runtime's recent sessions) |
| `bedrock-agentcore:ListAgentRuntimeEndpoints` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` | Contain (the Runtime's endpoint names, to find its session log groups). Without it only the DEFAULT endpoint is checked |
| `bedrock-agentcore:ListTagsForResource` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` | Contain and release, only in an account and Region that host cells of more than one tenant: the Runtime's own `tenant-id` tag says which tenant it belongs to. Not called where there is one tenant. Without it the tenant of a Runtime in a shared account cannot be determined, and only the `platform` role can act |
| `logs:DescribeLogStreams` | `arn:aws:logs:REGION:CELL:log-group:/aws/bedrock-agentcore/runtimes/*` | Contain (find the Runtime's recent session ids in the names of its session log streams) |
| `logs:StartQuery` (only with the spans option) | `arn:aws:logs:REGION:CELL:log-group:aws/spans:*` | Contain, when the cell sets `containmentSpans` (find session ids in the Runtime's spans) |
| `logs:GetQueryResults` (only with the spans option) | `*` (no resource-level permissions) | Same query |

`bedrock-agentcore:ListSessions` is not used and should not be granted for
this purpose: it lists the sessions of a Memory resource
(`/memories/{memoryId}/actor/{actorId}/sessions`), not of a Runtime. No API
lists a Runtime's sessions, so the session ids come from the names of its
session log streams, `runtime-logs-<session id>` in
`/aws/bedrock-agentcore/runtimes/<runtime id>-<endpoint>` (an agent that
writes output has them). If they cannot be read, containment still works
(invocation is denied) and the response says that running sessions could not
be listed.

By default the role reads stream names only. It has no permission to read a
log event (`logs:GetLogEvents`, `logs:FilterLogEvents`) and none to run a
query, and the code calls neither. It cannot invoke the Runtime or read its
configuration. It can read a Runtime's tags, and reads one of them: the
`tenant-id` tag, which the cell's pipeline sets.

**The spans option widens the role.** A cell that sets `containmentSpans`
also grants `logs:StartQuery` on its spans log group. IAM cannot restrict
which query is run, so with that option the role can read span content
(which can include prompts and tool output), not only session ids. Leave it
off unless a cell runs instrumented agents that write no output.

**What `PutResourcePolicy` means.** IAM cannot restrict the content of the
policy that is written. The code writes one deny statement and keeps every
other statement, but the permission itself would let whoever controls the
containment function write any resource policy on a Runtime of an opted-in
cell, including one that grants invocation to another account. The controls
are: the role is assumable only by the containment function's role with the
cell's external id; that function's code and role are protected authorities
of the Platform account; and every change is a CloudTrail management event
in the cell account, which the cell can alarm on (any `PutResourcePolicy` by
this role whose statement Sid is not `AgenticAIPortalContainment`).

## 7. Sweeper function (platform account, under the containment function role)

Function `sweep_handler.handler`, `PORTAL_ACTION_ROLE=sweeper`. It is invoked
by the sweep queue through an event source mapping and serves no route. The
mapping must hand it one message at a time (batch size 1): the function runs
an invocation that holds exactly one record and nothing of any other. It
runs under the containment function's role, so that the cells' containment
roles keep trusting exactly one role.

What the sweeper's code uses of the two roles:

| Call | Role | Action it uses (listed above) |
| --- | --- | --- |
| Assume the cell's containment role | containment function role | sts AssumeRole |
| Read the Runtime's containment history back to the contain a message names, and look at a claim that was refused | containment function role | dynamodb Query |
| Claim the sweep, then write its one audit event | containment function role | dynamodb PutItem |
| Read the Runtime's resource policy, to see that it is still contained | cell containment role | bedrock-agentcore GetResourcePolicy |
| List the Runtime's endpoints and the names of its session log streams | cell containment role | bedrock-agentcore ListAgentRuntimeEndpoints, logs DescribeLogStreams |
| Query the cell's spans for session ids, only with the spans option | cell containment role | logs StartQuery and GetQueryResults |
| Stop each session | cell containment role | bedrock-agentcore StopRuntimeSession |

The sweeper never writes or deletes a resource policy and never reads a
registry record: its code calls none of `PutResourcePolicy`,
`DeleteResourcePolicy` or `GetRegistryRecord` (`tests/test_readonly.py`
checks that). Of the audit table it uses three things, all under the
Runtime's own key: the history read back to the contain a message names
(`dynamodb:Query`), the claim of the sweep, and the sweep's one event (both
`dynamodb:PutItem`, with the condition that the item does not exist). The
event goes into the `OTHER#` range of the Runtime's partition.

**The session its code asks for cannot either.** The sweeper parses input
that anyone who can reach the queue or the function chose, so it asks for
less than the containment function uses. It assumes the cell's containment
role with a session policy (`session_policy` in
`portal_api/actions/sweeper.py`), and a session can do only what both the
role and that policy allow:

| The session policy allows | In which cells |
| --- | --- |
| `bedrock-agentcore:GetResourcePolicy`, `bedrock-agentcore:StopRuntimeSession`, `bedrock-agentcore:ListAgentRuntimeEndpoints`, `logs:DescribeLogStreams` | every cell |
| `logs:StartQuery`, `logs:GetQueryResults` | a cell with the spans option |

`PutResourcePolicy`, `DeleteResourcePolicy` and `ListTagsForResource` are not
among them. Its `Resource` is `*` because the role's own policy already names
the resources; the session policy only takes actions away. This needs no
change in any cell: a session policy travels with the `AssumeRole` request.

It is a restraint the sweeper's code puts on itself, not a limit on the role.
The function runs under the containment function's role, and that role may
assume a cell's role without a session policy. So the limit holds for the
code as it is: every assumption the sweeper makes goes through one function
that always passes the policy, and a test pins that. It would not hold for a
later change that left the policy out. A limit that does not depend on the
sweeper's code needs a role of the sweeper's own, which every cell's
containment role would have to trust under a condition; that is a change in
the cells and is not made here.

Reading the queue is done by the Lambda service with the function's role, not
by the code. The role therefore also needs, on the sweep queue only:
`sqs:ReceiveMessage`, `sqs:DeleteMessage` and `sqs:GetQueueAttributes`.

A queue encrypted with the key that Amazon SQS manages needs nothing more. A
queue encrypted with a customer managed AWS KMS key needs, on that key,
`kms:GenerateDataKey` and `kms:Decrypt` for the role (the first to send, the
second to send and to receive).

The message is input, not authority. It names a Runtime; the sweeper finds
the cell, the role and the external id in its own configuration, accepts the
Runtime's ARN only as the portal builds it for that cell, and stops sessions
only when the Runtime's policy holds the portal's statement at that moment.
Nor does the message prove that a contain sent it. The sweeper reads the
Runtime's history and runs a sweep only when a contain with the message's
request id is on record and scheduled sweeps, when the sweep is due and has
not left its event, and when no later containment has taken that contain's
place; it claims the sweep with a conditional write before it does anything
in the cell. Whoever can invoke the sweeper can therefore cause at most a
sweep that a contain scheduled, at the time it is due, and its one event: no
other sweep number is admitted than those the contain's result lists. A
message that is not valid, or whose sweep is not run, leaves nothing in the
table.

**Who can invoke the sweeper, and who can take a sweep away.** The queue
invokes it, and so can any principal of the Platform account that holds
`lambda:InvokeFunction` on it: nothing in the function restricts its
callers, which is why it trusts nothing in the event. A principal with
other rights on the queue could do the opposite and remove sweeps that are
waiting, by purging the queue or by receiving and deleting messages. A
message that waits longer than the queue keeps it is dropped without
reaching the dead-letter queue.

**As the construct deploys it.** The queue carries a resource policy
(statement `OnlyTheContainmentRoleHandlesMessages`) that denies `sqs:SendMessage`,
`sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility` and
`sqs:PurgeQueue` to every principal whose `aws:PrincipalArn` is not the
containment function's role (the role the Lambda service reads the queue
with), so an administrator of the Platform account can neither put a message
on it nor take one off it. The statement covers the queue's messages, not the
queue itself: a principal that may change the queue's attributes or delete
the queue can still make scheduled sweeps disappear. Two alarms notice sweeps
that are not being run:
one on the dead-letter queue, one on the age of the oldest message (one
hour). That is a second layer, not a replacement: the sweeper validates
every message as described above, whoever sent it.

### The audit table, by partition key

Each function reads and writes only its own part of the audit table. The
keys below are exact; a policy that narrows the table actions with a
`dynamodb:LeadingKeys` condition can use the patterns in the last column,
and the construct does so for the three action roles. Nothing below needs a
partition key or an action that the tables above do not already name: what
differs is the sort key, which IAM does not look at.

The sort key of an event begins with `EVENT#`. In a Runtime's partition
(`CONTAINMENT#<Runtime ARN>`) there is a second range, `OTHER#`, for the
events that cannot change who holds a containment (a sweep, a refusal, a
contain of a Runtime that is already contained and held, a release of one
that is not contained, an attempt that could not read the policy); an event
is written into one of the two and never into both, and a release reads the
first alone. Three kinds of item are not events, and no read of a history
returns them:

- The latest review attestation of a record: `RECORD#<record id>` in the
  partition `REVIEWS`. One item for a record, and the only item of the table
  that a later write may replace (by an attestation that was attested
  later). A table that holds attestations from before that has them under
  `EVENT#<UTC timestamp>#<record id>` in the same partition; nothing writes
  those any more and the read API still reads them.
- The sweeper's claim of a sweep: `SWEEP#<request id>#<sweep number>`, in the
  Runtime's own partition.
- The mark that a refusal, or an answer that nothing was changed, is on
  record for one person and one state of a record: `ONCE#<hash>`, in the
  record's own partition (or, for a refused create, in the partition of the
  record's name). The registrar and the approver function write it with
  `PutItem` and the usual condition, before the event; neither reads it.
  The containment function writes the same kind of mark in the Runtime's
  own partition, for a refused release: once for each person, rule and
  containment.

| Function (role) | Writes (`PutItem`) | Reads (`Query`) | Leading keys |
| --- | --- | --- | --- |
| Read API (read role) | nothing | `RECORD#<record id>`, `RECORD#NAME#<record name>`, `CONTAINMENT#<Runtime ARN>`, `REVIEWS` | `RECORD#*`, `CONTAINMENT#*`, `REVIEWS` |
| Registrar (registrar role) | `RECORD#<record id>`, `RECORD#NAME#<record name>` | nothing | `RECORD#*` |
| Approver (approver role) | `RECORD#<record id>`, `REVIEWS` | `RECORD#<record id>` | `RECORD#*`, `REVIEWS` |
| Containment (containment function role) | `CONTAINMENT#<Runtime ARN>`: events in either range, and marks | `CONTAINMENT#<Runtime ARN>` | `CONTAINMENT#*` |
| Sweeper (the same role) | `CONTAINMENT#<Runtime ARN>`: one claim and one event for each sweep | `CONTAINMENT#<Runtime ARN>` | `CONTAINMENT#*` |

- The registrar writes under `RECORD#NAME#<record name>` what is decided
  before a record has an id: the intent of a create, and the refusal of a
  create whose name is taken. `RECORD#*` covers both forms.
- The approver reads a record's own history to find its submitter (approve,
  reject and review) and its latest review (review). It never reads `REVIEWS`.
- The registrar role does not need `REVIEWS`. Without the condition it could
  write an attestation there, which only the approver may.
- The Runtime ARN in a key is always the one the function built from the
  cell's configuration (`portal_api/arns.py`), never one a caller wrote.
- No function reads a partition to its end: every read is bounded
  (`portal_api/aws/audit.py`).

## 8. Retire, review and the evidence document: no new action

Retiring a registration, attesting its review and the evidence document need
no IAM action beyond the tables above, and no new role. Which role runs which
call:

| Call | Role | Action it uses (already listed) |
| --- | --- | --- |
| Retire: read the record, set its status to `DEPRECATED`, read it back | approver role | agent-registry GetRegistryRecord and UpdateRegistryRecordStatus |
| Retire and review: write the intent and result events | approver role | dynamodb PutItem |
| Review, and every approval: write the record's latest attestation (partition key `REVIEWS`, one item for a record) | approver role | dynamodb PutItem |
| Review: read the record to see that it is approved | approver role | agent-registry GetRegistryRecord |
| Refuse a change to a retired record (update, submit) | registrar role | agent-registry GetRegistryRecord, dynamodb PutItem |
| Read the latest attestation of every record for the inventory (partition key `REVIEWS`, two queries) | read role | dynamodb Query |
| Evidence: the registration's events and the containment events | read role | dynamodb Query |
| Evidence: the Runtime's containment state | cell reader role | bedrock-agentcore GetResourcePolicy |
| Evidence: the policies of the agent's Tool Gateways (hashed, never returned) | cell reader role | bedrock-agentcore ListPolicies and GetPolicy |
| Evidence: the latest pipeline execution | read role | codepipeline ListPipelineExecutions and ListActionExecutions |

A review never calls `UpdateRegistryRecord` or `UpdateRegistryRecordStatus`,
and the approver role still cannot create, update or delete a record.

One thing to check in the table policy: the attestations live under the
partition key `REVIEWS` of the audit table. A policy that grants the actions
on the table ARN, as the tables above describe, covers it. A policy that
narrows them with a `dynamodb:LeadingKeys` condition must allow `REVIEWS` for
the read role's query and the approver role's write.

## 9. Token verification and the reference rule: no action

- **Token verification.** The read API and the registrar, approver and
  containment functions
  verify the caller's bearer token themselves. That needs no IAM action. It
  needs outbound HTTPS from the function to the token issuer's key set, read
  once per execution environment and then cached (README, "Identity"). Keys
  fetched more than 48 hours ago are not used, so a function that cannot
  reach the issuer for that long answers 503 until it can. The read function
  needs that way out as well now, and the token variables
  (`PORTAL_JWT_ISSUER`, `PORTAL_JWT_AUDIENCE`, and `PORTAL_JWKS_URL` for
  Entra): without them it answers 500 on every data endpoint.
- **The reference rule (`REG-13-N`).** The registrar and approver functions
  read `PORTAL_CELLS` to know which tenant runs where. They make no call for
  it and assume no role in a cell.
- **The tenant in a shared account.** The one new action of this set is
  `bedrock-agentcore:ListTagsForResource` on the cell's containment role
  (section 6).

## 10. Notes on the action set

**Tag reads in the cell reader role:** `bedrock-agentcore:ListTagsForResource`
on `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` and
`arn:aws:bedrock-agentcore:REGION:CELL:gateway/*`.

The code tolerates its absence (the call fails, a warning is logged, tags read
as empty), but then nothing can be matched to a cell by its tenant, agent and
environment tags. The effect: discovered agents and gateways have no tenant or
environment of their own, a discovered runtime gets no release evidence and no
tag-derived gateway link. Registered agents are unaffected, because their
identity comes from the registry record.

Actions considered for these roles that this code does not call (not needed
for milestone 1):

- Portal role: agent-registry GetRegistry; codepipeline GetPipelineState and
  GetPipelineExecution.
- Cell reader role: bedrock-agentcore ListAgentRuntimeEndpoints,
  GetPolicyEngine, ListPolicyEngines, GetMemory, ListMemories; cloudwatch
  ListMetrics; logs StopQuery and DescribeLogGroups.

Evidence for the action names:

- The operations called are the SDK operations `ListPolicies` and `GetPolicy`
  on the `bedrock-agentcore-control` client (botocore 1.43.127). The SDK also
  has separate `ListPolicySummaries` and `GetPolicySummary` operations; this
  code does not call them. Both `ListPolicies` and `GetPolicy` were called
  successfully against a live policy engine with an administrator profile,
  which confirms the operations and their response shape but not the IAM
  action names. The names above assume the usual one-to-one mapping from API
  operation to IAM action.
- The registry client's SDK signing name is `agent-registry` and registry ARNs
  are `arn:aws:agent-registry:...`, which is why the prefix is written as
  `agent-registry`. The same caveat applies: it was exercised only with an
  administrator profile.
- The policy engine the code reads is the one named in the gateway's
  `policyEngineConfiguration.arn` from `GetGateway`, so neither
  `ListPolicyEngines` nor `GetPolicyEngine` is needed.
- The platform account's own runtimes and gateways are read only through a
  reader role, when the platform account is listed in `PORTAL_CELLS`. The
  portal role makes no `bedrock-agentcore` call.
