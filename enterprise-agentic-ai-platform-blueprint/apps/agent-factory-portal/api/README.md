# Agent Factory Portal API

Back end of the Agent Factory Portal, the product surface for the
blueprint's planes (developer experience, platform control, assurance and
operations). It serves blueprint data in the response shapes the portal front
end (`../web`) already uses.

The bundle holds three Lambda functions, each with its own IAM role:

| Handler | Purpose |
| --- | --- |
| `handler.handler` | The read API. Every route is a `GET` |
| `registrar_handler.handler` | Create, update, submit and delete agent records |
| `approver_handler.handler` | Approve or reject a submitted agent record |

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
| `/catalog/models` | `PORTAL_MODEL_ALLOWLIST` |
| `/catalog/tools` | Registry tool records |
| `/registrations` | Agent governance records in the registry, with `status` and `tenant_id` filters |
| `/registrations/{record_id}` | One record, with who created, submitted and decided it (from the audit trail) |
| `/registrations/{record_id}/history` | The record's audit trail, newest first |

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

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `PORTAL_ENV` | yes | `nonprod` or `prod` |
| `PORTAL_REGISTRY_ID` | yes | Id of the platform Agent Registry (tool records; also agent records unless the next variable is set) |
| `PORTAL_AGENT_REGISTRY_ID` | no | Id of a separate registry, in the same Region, that holds the agent governance records. Use it when the platform registry auto-approves, so that agent records wait for a person |
| `PORTAL_REGISTRY_REGION` | yes | Region of the registry. Also used for the other platform-account reads (pipelines, guardrails) |
| `PORTAL_CELLS` | yes | JSON list of `{ tenantId, agentId, applicationId?, environment, accountId, region, readerRoleArn, externalId?, alarmNamePrefix?, pipelineName?, accountAlias? }` |
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
| `PORTAL_ACTION_ROLE` | `registrar` or `approver`; must match the handler |
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
`registrar_handler.py` and `approver_handler.py` at its root. Zip the contents of `dist/`. boto3 and botocore are bundled
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
