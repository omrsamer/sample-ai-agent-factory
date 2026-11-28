# Agent Factory Portal API

Back end of the Agent Factory Portal, the product surface for the
blueprint's planes (developer experience, platform control, assurance and
operations). It serves blueprint data in the response shapes the portal front
end (`../web`) already uses.

The bundle holds four Lambda functions, each with its own IAM role:

| Handler | Purpose |
| --- | --- |
| `handler.handler` | The read API. Every route is a `GET` |
| `registrar_handler.handler` | Create, update, submit and delete agent records |
| `approver_handler.handler` | Approve or reject a submitted agent record |
| `containment_handler.handler` | Contain or release an agent's Runtime |

The read API is read-only by construction:

- Every route is a `GET`. Any other method is answered with `405` before a
  route or dependency runs.
- Its code calls only list, get, describe and query operations, plus
  `logs:StartQuery` to run read-only CloudWatch Logs Insights queries, and it
  does not import the action code. `tests/test_readonly.py` enforces this and
  keeps [IAM_ACTIONS.md](IAM_ACTIONS.md) exact for all three roles.
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
| `/mcp-servers`, `/mcp-servers/{id}` | One per AgentCore Gateway in a cell account. Tools are the gateway targets joined with registry tool records (`agenticai.tool-governance/1.0`) |
| `/mcp-servers/{id}/policies` | Policies of the gateway's AgentCore Policy Engine. Cedar text is returned as stored and marked not editable |
| `/mcp-servers/{id}/policy-enforcement` | `none`, `log_only` or `enforce`, from the gateway's policy engine configuration |
| `/mcp-servers/{id}/grants` | The same derived edges, seen from the gateway |
| `/governance-graph` | Nodes `group`, `agent`, `mcp`; edges `access` (owner group to agent) and `can_call` (agent to gateway). No `user` nodes in the default profile |
| `/principals/{id}`, `/governance-graph/principals/{id}` | Detail of an owner group that appears in the graph |
| `/observability/settings`, `/observability/metrics` | CloudWatch back end marker; fleet metrics per agent |
| `/guardrails`, `/guardrails/{id}` | Amazon Bedrock guardrails in the platform account. Filtered to those that carry the configured tag when one is set; otherwise all of them |
| `/fleet/health` | Per cell: CloudWatch alarms by name prefix, reduced to `healthy`, `needs_attention`, `critical` or `no_data`. An unreachable cell is reported, not fatal |
| `/fleet/summary` | Counts of agents by inventory state, lifecycle, risk level and flag, and of gateways by policy mode |
| `/agents/export` | The inventory as a CSV or JSON download |
| `/agents/{id}/containment` | Whether the agent's Runtime is contained, by whom, and the containment events |
| `/omni/observed-services` | Services the CloudWatch Omni Context Graph observes in the portal's own account, marked registered or not |
| `/catalog/models` | `PORTAL_MODEL_ALLOWLIST` |
| `/catalog/tools` | Registry tool records |
| `/registrations` | Agent governance records in the registry, with `status` and `tenant_id` filters |
| `/registrations/{record_id}` | One record, with who created, submitted and decided it (from the audit trail) |
| `/registrations/{record_id}/history` | The record's audit trail, newest first |

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

Every agent carries `flags` and `risk`. Each flag is `true`, `false`, or
`null` when it cannot be known.

| Flag | True when | Null when |
| --- | --- | --- |
| `unmanaged` | The agent has no registration in status APPROVED (including every `detected_only` agent) | never |
| `ownerless` | The registration names no owner group, or `PORTAL_OWNER_GROUPS` is set and the owner group is not in it. The accountable owner is the owner group; `sponsor` and `contact` are optional and do not enter this flag | the agent has no registration |
| `review_overdue` | The registration's `review_by` date is before today (UTC). No date means not overdue | the agent has no registration |
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

| Code | Severity | Applies when |
| --- | --- | --- |
| `RISK_CLASS_UNACCEPTABLE` | critical | The registration's risk class is `unacceptable` |
| `INBOUND_AUTH_NONE` | critical | The Runtime's inbound authorizer is `NONE` (unauthenticated calls) |
| `UNREGISTERED` | high | The agent has no registration at all (every `detected_only` agent) |
| `REGISTRATION_REJECTED` | high | The registration's status is `REJECTED` and a detection source still sees its Runtime |
| `REGISTRATION_DEPRECATED` | high | The registration's status is `DEPRECATED` and a detection source still sees its Runtime |
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

`GET /agents/export?format=csv|json` returns one row per agent as a download.
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
- **Who.** `portal_api/actions/containment_rules.py` (pure): contain needs
  `security`, `platform` or `sre`; release needs `security` or `platform` and a
  different person from the one who contained it; the caller must hold the
  agent's tenant.
- **Which tenant.** `tenant_for` in the same module: the tenant is decided by
  where the Runtime runs (the cells configured for its account and Region),
  never by what a registration claims. One tenant there: that tenant. Several
  (a shared account): the tenant of the agent's registration, only when it is
  approved and names one of them. Otherwise the tenant cannot be determined
  and only `platform` may act. A draft that names another tenant's Runtime
  therefore gives nobody authority over it.
- **Where.** Everything in the cell is done by assuming the cell's
  `containmentRoleArn` with the cell's `externalId`. A cell without one
  cannot be contained (409).
- **Resolving the agent.** A registered agent's Runtime ARN is read from its
  registry record, never taken from the request. An agent with no
  registration is addressed by its Runtime id.
- **Audit.** Same table and discipline as registrations, under
  `pk = CONTAINMENT#<Runtime ARN>`: the history belongs to the Runtime the
  request resolved to, not to the id the caller used, so the two-person rule
  holds whichever id a request uses. An intent event is written before
  anything is changed and a result event says what was and was not done. A
  repeated contain is recorded as `unchanged` and does not replace the
  holder; a contain that failed after the statement may have been written
  still names a holder. A caller without the role is refused before anything
  is resolved; that refusal goes to the function's log, not to the table,
  because its key would be the caller's own choice.
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
- **Audit trail.** Every decision is appended to the Amazon DynamoDB table in
  `PORTAL_AUDIT_TABLE` (`pk = RECORD#<record_id>`,
  `sk = EVENT#<UTC timestamp>#<uuid>`). For an allowed action an `intent` event
  is written first; if that write fails the action is not performed. A
  `result` event follows the registry call. Events are written with
  `attribute_not_exists(pk)` and never updated or deleted. The `result` event
  of an approval also stores the approved document (attribute `document`), so
  a later change can be shown against it.
- **Separation of duties.** The submitter of a record is the actor of its
  latest allowed `submit` event, read from the audit table with a strongly
  consistent query. The submitter cannot approve or reject the record.
- **Fail closed.** A function whose `PORTAL_ACTION_ROLE` does not match its
  handler answers 404 for everything. Each function answers 404 for the other
  functions' routes.

## Identity

The API runs behind an Amazon API Gateway HTTP API with a JWT authorizer, which
validates signature, issuer and audience. The function reads the validated
claims from the event. `PORTAL_IDENTITY_PROVIDER` selects how they are read:

- `cognito`: subject `sub`, groups from the union of `cognito:groups` and
  `custom:groups` (the claim a SAML workforce identity provider's groups are
  mapped to; a comma-separated or JSON array string). The API receives the
  Cognito ID token.
- `entra`: subject `oid`, app roles from `roles`, groups from `groups`.

`PORTAL_GROUP_ROLE_MAP` maps a group or app role name to one of `platform`,
`security`, `sre`, `approver`, `finops`, `developer`, `readonly`. The highest
mapped role wins. No claims is `401`; no mapped group is `403`.

**What the functions trust.** The functions do not verify the token a second
time: they trust the claims API Gateway passes after its own verification.
API Gateway is the only caller the functions' resource policies allow, but a
principal of the Platform account who holds `lambda:InvokeFunction` on a
function can call it directly with claims of its own making, and so act as
any persona, including for an approval, a containment or a release. Treat
that permission on the portal's functions as a protected authority of the
Platform account (deny it by service control policy or permission boundary
to everyone but the deployment role), as for the functions' roles and code.
Verifying the token inside the action functions is on the roadmap.

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
| `PORTAL_CELLS` | yes | JSON list of `{ tenantId, agentId, applicationId?, environment, accountId, region, readerRoleArn, externalId?, alarmNamePrefix?, pipelineName?, accountAlias?, containmentRoleArn?, omniDomainUrl?, omniRegion? }` |
| `PORTAL_IDENTITY_PROVIDER` | yes | `cognito` or `entra` |
| `PORTAL_GROUP_ROLE_MAP` | yes | JSON object, group or app role name to portal role |
| `PORTAL_GUARDRAIL_TAG_KEY`, `PORTAL_GUARDRAIL_TAG_VALUE` | no | Tag that marks a guardrail as part of the blueprint. Both empty (the default): every guardrail in the account and Region is listed and tags are not read. Set both or neither |
| `PORTAL_MODEL_ALLOWLIST` | yes | JSON list of model ids, or of `{ modelId, provider?, regions?, status? }` |
| `PORTAL_ALLOWED_ORIGINS` | no | JSON list of origins for CORS. Default: none. `*` is rejected |
| `PORTAL_CACHE_TTL_SECONDS` | no | In-process cache lifetime for list reads. Default `30`, `0` disables |
| `PORTAL_LOG_LEVEL` | no | Default `INFO` |
| `PORTAL_AUDIT_TABLE` | for history | Audit table name. Without it `/registrations/{record_id}/history` answers 500 and `/registrations/{record_id}` omits the people fields |
| `PORTAL_GROUP_TENANT_MAP` | no | Lets `/users/me` report `registration_tenants` |
| `PORTAL_DEV_AUTH` | no | Local development only, see below |

The action functions read a smaller set, all required unless noted:

| Variable | Meaning |
| --- | --- |
| `PORTAL_ACTION_ROLE` | `registrar`, `approver` or `containment`; must match the handler |
| `PORTAL_CELLS` | Containment function only, required there: the cells, with `containmentRoleArn` and `externalId` on those that opt in |
| `PORTAL_ENV`, `PORTAL_REGISTRY_ID`, `PORTAL_REGISTRY_REGION` | As above, except that `PORTAL_REGISTRY_ID` here is the registry that holds the agent records (the agent registry when there are two). The audit table is read in the registry's Region |
| `PORTAL_IDENTITY_PROVIDER`, `PORTAL_GROUP_ROLE_MAP` | As above |
| `PORTAL_GROUP_TENANT_MAP` | JSON object, group or app role name to a list of tenant ids. `"*"` is allowed only for a group mapped to `platform` |
| `PORTAL_AUDIT_TABLE` | Audit table name |
| `PORTAL_ALLOWED_ORIGINS`, `PORTAL_LOG_LEVEL` | Optional, as above |

If a required value is missing or malformed, every data endpoint answers `500`
with a reason that names the variable, and the reason is logged. There is no
fallback to sample data.

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
Local runs use your own AWS credentials for the platform account and still
assume each cell's reader role.

## Build

```bash
./build.sh
```

Produces `dist/` for arm64, Python 3.13 Lambda functions, with `handler.py`,
`registrar_handler.py`, `approver_handler.py` and `containment_handler.py` at
its root. Zip the contents of `dist/`. boto3 and botocore are bundled
at pinned versions on purpose: the Agent Registry control-plane client is newer
than the SDK included in the Lambda runtime.

Function settings used by the infrastructure: Python 3.13 on arm64, timeout 29 seconds, memory 1024 MB. The source stays compatible with Python 3.12.

## Test

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check .
```

Tests use botocore `Stubber` and hand-written fakes. They never call AWS.

## Licence

MIT-0, except `portal_api/models/wire.py`, which is derived from an
Apache-2.0 project and carries its own header.
