# IAM actions used by the Agent Factory Portal API

This file lists every IAM action the code calls, per role, and nothing else.
`tests/test_readonly.py` fails if a role's code calls an operation that is not
in its table, or if a table lists an action that role's code does not call.

There are four Lambda functions, each with its own role, plus the reader role
in each cell account and, where a cell opts in, a containment role:

| Function | Handler | Role | Can change |
| --- | --- | --- | --- |
| Read API | `handler.handler` | read role | Nothing |
| Registrar | `registrar_handler.handler` | registrar role | Registry records (create, update, submit, delete); appends audit events |
| Approver | `approver_handler.handler` | approver role | A registry record's status; appends audit events |
| Containment | `containment_handler.handler` | containment function role, and each opted-in cell's containment role | One deny statement in a Runtime's resource policy; stops Runtime sessions; appends audit events |

The read API has no code path that creates, updates, deletes, tags or invokes
anything, and it does not import the action code at all.

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
| `dynamodb:Query` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | `/registrations/{record_id}`, `/registrations/{record_id}/history` |
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
| `agent-registry:GetRegistryRecord` | The registry's record ARNs | `POST /registrations/{record_id}/approve`, `POST /registrations/{record_id}/reject` |
| `agent-registry:UpdateRegistryRecordStatus` | The registry's record ARNs | Same two routes |
| `dynamodb:Query` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | Same two routes (who submitted the record; strongly consistent read) |
| `dynamodb:PutItem` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | Same two routes (audit events) |

Neither action role has `dynamodb:UpdateItem` or `dynamodb:DeleteItem`, and the
code writes with the condition `attribute_not_exists(pk)`, so an audit event
can be added but never changed or removed through the API. The approver role
cannot create, update or delete a record; the registrar role cannot set a
record's status.

## 5. Containment function role (platform account)

Function `containment_handler.handler`, `PORTAL_ACTION_ROLE=containment`.

| Action | Resource it can be narrowed to | Needed by |
| --- | --- | --- |
| `sts:AssumeRole` | The `containmentRoleArn` of each cell that opts in (exact role ARNs) | Both containment routes. Everything in the cell is done with that role |
| `agent-registry:GetRegistryRecord` | The records of the registry that holds the agent records (this function's `PORTAL_REGISTRY_ID`) | Both routes, for a registered agent: its Runtime ARN and tenant are read from its record, never taken from the request |
| `dynamodb:Query` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | Both routes (who contained the agent, for the two-person rule; strongly consistent read) |
| `dynamodb:PutItem` | `arn:aws:dynamodb:REGION:PLATFORM:table/AUDIT_TABLE` | Both routes (audit events) |

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
configuration.

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

## 7. Notes on the action set

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
