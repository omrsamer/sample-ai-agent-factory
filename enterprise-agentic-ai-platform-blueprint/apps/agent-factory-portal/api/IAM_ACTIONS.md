# IAM actions used by the Agent Factory Portal API

This file lists every IAM action the code calls, and nothing else. All of them
are read actions. The API has no code path that creates, updates, deletes,
tags or invokes anything. `tests/test_readonly.py` fails if the code calls an
operation that is not listed here, or if this file lists an action the code
does not call.

Placeholders: `PLATFORM` is the platform account id, `CELL` is a cell account
id, `REGION` is the Region of the resource.

## 1. Portal Lambda role (platform account)

Region for every platform-account call is `PORTAL_REGISTRY_REGION`.

| Action | Resource it can be narrowed to | Needed by |
| --- | --- | --- |
| `sts:AssumeRole` | The `readerRoleArn` of each entry in `PORTAL_CELLS` (exact role ARNs, no wildcard) | Every endpoint that reads a cell: `/agents*`, `/mcp-servers*`, `/governance-graph`, `/principals/{id}`, `/observability/metrics`, `/fleet/health` |
| `agent-registry:ListRegistryRecords` | `arn:aws:agent-registry:REGION:PLATFORM:registry/<PORTAL_REGISTRY_ID>` | `/agents*`, `/mcp-servers*`, `/governance-graph`, `/principals/{id}`, `/observability/metrics`, `/catalog/tools` |
| `agent-registry:GetRegistryRecord` | `arn:aws:agent-registry:REGION:PLATFORM:registry/<PORTAL_REGISTRY_ID>/record/*` | Same as `ListRegistryRecords` (the list operation does not return descriptors) |
| `codepipeline:ListPipelineExecutions` | `arn:aws:codepipeline:REGION:PLATFORM:<pipelineName>` for each `pipelineName` in `PORTAL_CELLS` | `/agents/{id}/evals/runs` |
| `codepipeline:ListActionExecutions` | Same pipeline ARNs | `/agents/{id}/evals/runs` (EvaluationGate action result) |
| `bedrock:ListGuardrails` | `*` (list operation) | `/guardrails`, `/guardrails/{id}` |
| `bedrock:ListTagsForResource` | `arn:aws:bedrock:REGION:PLATFORM:guardrail/*` | `/guardrails`, `/guardrails/{id}`. Called only when `PORTAL_GUARDRAIL_TAG_KEY` is set (tag filter); not needed when it is empty |
| `bedrock:GetGuardrail` | `arn:aws:bedrock:REGION:PLATFORM:guardrail/*` | `/guardrails/{id}` |

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
| `bedrock-agentcore:ListAgentRuntimeVersions` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` | `/agents/{id}/deployments` |
| `bedrock-agentcore:ListGateways` | `*` (list operation) | `/mcp-servers*`, `/agents*`, `/governance-graph`, `/principals/{id}`, `/observability/metrics` |
| `bedrock-agentcore:GetGateway` | `arn:aws:bedrock-agentcore:REGION:CELL:gateway/*` | Same as `ListGateways` (URL, authorizer type, policy engine configuration) |
| `bedrock-agentcore:ListGatewayTargets` | `arn:aws:bedrock-agentcore:REGION:CELL:gateway/*` | Same as `ListGateways` (tools) |
| `bedrock-agentcore:GetGatewayTarget` | `arn:aws:bedrock-agentcore:REGION:CELL:gateway/*` | Same as `ListGateways` (tool schemas) |
| `bedrock-agentcore:ListTagsForResource` | `arn:aws:bedrock-agentcore:REGION:CELL:runtime/*` and `arn:aws:bedrock-agentcore:REGION:CELL:gateway/*` | Same as `ListAgentRuntimes` and `ListGateways` (tenant, agent and environment tags). Optional: without it, tags read as empty |
| `bedrock-agentcore:ListPolicies` | `arn:aws:bedrock-agentcore:REGION:CELL:policy-engine/*` | `/mcp-servers/{id}/policies` |
| `bedrock-agentcore:GetPolicy` | `arn:aws:bedrock-agentcore:REGION:CELL:policy-engine/*/policy/*` | `/mcp-servers/{id}/policies` (only when the list response omits the Cedar statement) |
| `cloudwatch:DescribeAlarms` | `arn:aws:cloudwatch:REGION:CELL:alarm:*` | `/fleet/health` |
| `cloudwatch:DescribeAlarmHistory` | `arn:aws:cloudwatch:REGION:CELL:alarm:<alarm name prefix>*` | `/fleet/health` (only for alarms whose state changed in the last 24 hours) |
| `cloudwatch:GetMetricData` | `*` (no resource-level permissions) | `/agents/{id}/metrics`, `/observability/metrics` |
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

## 3. Notes on the action set

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
