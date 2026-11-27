# Agent Factory Portal: API contract

This is the hand-off between the web front end in this directory and the portal API. It lists
every request the front end makes. The source of truth for the types is
[`src/api/client.ts`](src/api/client.ts) and [`src/types/index.ts`](src/types/index.ts); the test
`src/api/client.test.ts` fails if the paths or query parameters below change.

## Rules that apply to every endpoint

- **Read-only by default.** With `features.governedActions` off (the default) every request is
  a `GET`: the front end sends no `POST`, `PUT`, `PATCH` or `DELETE` and no request body, and
  the code that could is never downloaded. With it on, the front end additionally calls the
  registration endpoints in the last section, and writes only to `/registrations...`.
- **Base path.** Paths below are relative to `apiBaseUrl` from `/config.json`, which already ends
  in `/api/v1` (for example `GET {apiBaseUrl}/agents` is `GET /api/v1/agents`).
- **Authentication.** Each request carries `Authorization: Bearer <token>` and
  `Accept: application/json`. No other custom header is sent (no `x-user-email`, no
  `Content-Type` on a `GET`), so a CORS configuration for the read API only has to allow the
  `authorization` request header. A write with a body also sends
  `Content-Type: application/json`.
  - `authProvider: "cognito"`: the token is the Cognito **ID token** (`token_use: "id"`), whose
    `aud` is the app client id. The access token is never sent.
  - `authProvider: "entra"`: the token is the Entra **access token** for `entra.apiScope`.
- **401.** On a 401 the front end obtains a fresh token and retries the request once. If the retry
  is also refused it reloads the page once; a further 401 is reported to the user as a sign-in
  configuration problem. An API must therefore answer 401 only for a missing, expired or
  invalid token, and 403 for a valid token that lacks permission.
- **Errors.** A non-2xx response should carry `{ "detail": string }` (type `ApiError`). `detail`
  may also be a list of `{ loc: (string | number)[], msg: string, type?: string }`. The text is
  shown to the user as is, so it must not contain a token, an ARN with an account id, or a
  response body from another service.
- **404.** The detail pages show a "not found" state for a 404 on `GET /agents/{id}` and
  `GET /mcp-servers/{id}`. A 404 on `GET /agents/{id}/evals/runs` is shown as "No release
  evidence" and a 404 on `GET /agents/{id}/runtime` as "No runtime is recorded".
- **Unknown fields are ignored.** The API may return more fields than are listed here.
  Optional fields (`?`) may be absent or `null`.
- **Identifiers in paths** are sent through `encodeURIComponent`.
- **Timestamps** are ISO 8601 strings in UTC. **Dates** in query parameters are `YYYY-MM-DD`.

## Endpoint summary

| # | Method | Path | Query parameters | Response type |
|---|--------|------|------------------|---------------|
| 1 | GET | `/users/me` | none | `CurrentUser` |
| 2 | GET | `/agents` | `lifecycle_state?` | `Agent[]` |
| 3 | GET | `/agents/{id}` | none | `Agent` |
| 4 | GET | `/agents/{id}/runtime` | `stage?` | `RuntimeStatus` |
| 5 | GET | `/agents/{id}/deployments` | `stage?`, `limit?` | `Deployment[]` |
| 6 | GET | `/agents/{id}/traces` | `page`, `limit` | `TracePage` |
| 7 | GET | `/agents/{id}/metrics` | `date_from`, `date_to` | `AgentMetrics` |
| 8 | GET | `/agents/{id}/evals/runs` | none | `EvalRuns` |
| 9 | GET | `/agents/{id}/mcp-grants` | none | `AgentMcpGrant[]` |
| 10 | GET | `/mcp-servers` | `lifecycle_state?` | `McpServer[]` |
| 11 | GET | `/mcp-servers/{id}` | none | `McpServer` |
| 12 | GET | `/mcp-servers/{id}/policies` | none | `CedarPolicySet` |
| 13 | GET | `/mcp-servers/{id}/policy-enforcement` | none | `CedarEnforcement` |
| 14 | GET | `/mcp-servers/{id}/grants` | none | `Grant[]` |
| 15 | GET | `/governance-graph` | none | `GovernanceGraph` |
| 16 | GET | `/principals/{id}` | `kind` | `PrincipalDetail` |
| 17 | GET | `/observability/settings` | none | `ObservabilitySettings` |
| 18 | GET | `/observability/metrics` | `scope`, `date_from`, `date_to` | `ScopeMetrics` |
| 19 | GET | `/guardrails` | none | `GuardrailTemplate[]` |
| 20 | GET | `/guardrails/{id}` | none | `GuardrailTemplate` |
| 21 | GET | `/fleet/health` | none | `FleetHealth` |
| 22 | GET | `/catalog/models` | none | `CatalogModel[]` |
| 23 | GET | `/catalog/tools` | none | `CatalogTool[]` |

Endpoints 1 to 20 keep the wire shapes of the upstream console the portal is derived from.
Endpoints 21 to 23 are new in the portal.

Which screen calls what:

| Screen | Endpoints |
|--------|-----------|
| Every screen (profile in the sidebar) | 1 |
| Fleet | 2, 10, 21 |
| Agents (list) | 2 |
| Agent detail: Overview | 3 |
| Agent detail: Tool subscriptions | 9 |
| Agent detail: Deployment | 4, 5 |
| Agent detail: Traces | 6 |
| Agent detail: Cost | 7 |
| Agent detail: Release evidence | 8 |
| Tool gateways (list) | 10 |
| Tool gateway detail: Overview, Tools | 11 |
| Tool gateway detail: Policies | 12, 13 |
| Tool gateway detail: Connected agents | 14, 2 |
| Access graph | 15, 16 (a user or group node is selected), 12 (a policy edge is selected) |
| Observability | 17, 18 |
| Release evidence | 2, 8 |
| Governance catalog: Agents | 2 |
| Governance catalog: Tools | 23 |
| Governance catalog: Guardrail profiles | 19, 20 (a profile is expanded) |
| Governance catalog: Models | 22 |

## Shared value types

```ts
type LifecycleState = 'proposed' | 'pending_approval' | 'approved' | 'rejected' | 'deprecated' | 'discovered';
                                   // 'discovered': a runtime found in a cell with no registry record; shown as "Discovered, not registered"
type Platform = string;            // 'aws_bedrock' for Workstream cells; other values are shown as recorded
type DataClassification = 'Public' | 'Internal' | 'Confidential' | 'Restricted';
type Origin = 'Deployed' | 'Registered';
type AuthType = 'none' | 'entra' | 'api_key';
type IdentityStatus = 'none' | 'pending' | 'provisioned' | 'failed';
type McpServerKind = 'gateway' | 'standard' | 'runtime';
type CedarEnforcementMode = 'none' | 'log_only' | 'enforce';
```

The front end tolerates values outside these unions: an unknown lifecycle state, platform,
runtime status, deployment outcome, guardrail status or catalog status is displayed as recorded,
and an unknown Cedar enforcement mode is displayed as "Enforcement mode unknown". It never
assumes "healthy", "ready" or "enforcing" for a value it does not recognise.

`auth_type` is displayed as: `none` "None recorded", `entra` "OIDC bearer token", `api_key`
"API key". The value `aws_iam` is also recognised and displayed as "AWS IAM (SigV4)"; any other
value is shown as recorded.

## 1. `GET /users/me` returns `CurrentUser`

The caller as the API sees them. The API decides the role; the front end only displays it.

```ts
interface CurrentUser {
  email: string;
  role: string;            // displayed, for example "viewer"
  role_level: number;      // 0 viewer, 1 operator, 2 admin
  can_deploy: boolean;     // not used in milestone 1
  oid: string | null;      // not used in milestone 1
  name: string | null;     // display label: name, then email. A value shaped like a UUID is treated as a token subject and not shown
  tenants: UserTenant[];
  can_register?: boolean;  // governed actions only: may create, edit, submit and delete registrations
  can_approve?: boolean;   // governed actions only: may approve and reject, and sees the Approvals screen
  registration_tenants?: string[] | null;  // tenants the caller acts for; ["*"] or null means the UI does not restrict by tenant
}
interface UserTenant {
  id: string;
  name: string;
  line_of_business: string;       // not displayed
  stages: Record<string, unknown>; // not read; may be {}
}
```

Used for: the profile in the sidebar; resolving `tenant_id` values to tenant names on every
screen (an id that is not in `tenants` is shown as the raw id); and `role_level >= 2` offers the
"Platform" scope on the Observability screen. If this request fails the portal still works and
shows identity-provider claims in the profile.

The profile label is `name`, then `email`, then the identity provider's name or email claim.
The token subject is never displayed; if nothing else is known the label is "Signed in".

`can_register`, `can_approve` and `registration_tenants` only decide which controls are
offered. Only the boolean `true` grants an authority. The action endpoints enforce every rule
themselves, and a refusal is displayed.

## 2. `GET /agents` returns `Agent[]`

Query: `lifecycle_state?: LifecycleState` (server-side filter; omitted for "all").

## 3. `GET /agents/{id}` returns `Agent`

```ts
interface Agent {
  id: string;
  name: string;                       // display name; for a registered agent, its agent id
  record_name?: string | null;        // registry record name; shown under "Record" when present
  purpose?: string;
  sponsor_oid?: string | null;        // not displayed
  sponsor_email?: string | null;      // owner; the part before "@" is displayed
  business_unit?: string | null;
  region?: string | null;
  data_classification?: DataClassification | null;
  platform?: Platform | null;
  framework?: string | null;
  mcp_server_ids: string[];           // not displayed directly; see endpoint 9
  declared_mcp_server_ids?: string[]; // tool gateways the agent descriptor declares
  origin: Origin;                     // 'Deployed' shows the Deployment tab
  entra_app_id?: string | null;       // not displayed
  entra_api_app_id?: string | null;   // not displayed
  entra_sp_id?: string | null;        // matched against Grant.principal_id (endpoint 14)
  entra_app_audience?: string | null; // not displayed
  invoker_role_id?: string | null;    // not displayed
  admin_role_id?: string | null;      // not displayed
  identity_status: IdentityStatus;    // displayed as "Workload identity"
  lifecycle_state: LifecycleState;
  endpoint_url?: string | null;
  auth_type: AuthType;
  agent_arn?: string | null;          // runtime ARN of the most recently deployed environment
  agent_arns?: Record<string, string> | null; // environment -> runtime ARN; keys feed the environment selector
  runtime_handle?: string | null;     // shown when agent_arn is absent
  runtime_kind?: string | null;       // not displayed
  tenant_id?: string | null;
  created_at: string;
  updated_at: string;
  created_by?: string | null;
}
```

ARNs are displayed with the account id masked to its last four digits; the copy button copies
the full value. If the full account id should not reach the browser, mask it in the API.

## 4. `GET /agents/{id}/runtime` returns `RuntimeStatus`

Query: `stage?: string`. Sent only when the user picks an environment (a key of
`Agent.agent_arns`); omitted means "the most recently deployed environment". If the API ignores
`stage`, the front end notices that the returned `stage` differs from the requested one and says
so instead of presenting the reading as the requested environment.

```ts
interface RuntimeStatus {
  agent_id: string;
  stage: string;                 // the environment this reading describes
  status: string;                // see below
  runtime_arn?: string | null;
  image_tag?: string | null;
  checked_at: string;
  detail?: string | null;        // short, safe hint; shown as text
}
```

`status` is matched case-insensitively: `ready` or `active` "Ready"; `creating`, `updating`,
`deleting`; `failed`, `create_failed`, `update_failed`; `not_deployed`. Anything else, including
an empty value, is displayed as "Unknown".

## 5. `GET /agents/{id}/deployments` returns `Deployment[]`

Query: `stage?: string` (as for endpoint 4), `limit?: number` (the front end sends `25`).
Newest first. The front end also filters the returned rows by `stage` when an environment is
selected, so an API that ignores `stage` still yields a correct list (within `limit`).

```ts
interface Deployment {
  id: string;
  repo_id: string;                // not displayed
  agent_id?: string | null;       // not displayed
  mcp_server_id?: string | null;  // not displayed
  stage: string;                  // environment
  seq_key: string;                // not displayed
  image_tag: string;
  source_sha?: string | null;     // first 7 characters displayed
  build_id?: string | null;       // not displayed
  outcome: 'started' | 'succeeded' | 'failed';
  actor?: string | null;          // displayed as "@actor" when actor_kind is 'github', else as recorded; absent shows a dash
  actor_kind?: string | null;
  started_at: string;
  completed_at?: string | null;   // not displayed
  error?: string | null;          // short, safe hint; shown as a tooltip on the outcome
}
```

## 6. `GET /agents/{id}/traces` returns `TracePage`

Query: `page: number` (1-based), `limit: number` (the front end sends `20`). `total` is the
number of traces across all pages and drives the pager.

```ts
interface TracePage {
  data: TraceRow[];
  total: number;
  warnings?: string[];           // short, safe notes about gaps in the data; shown above the table
}
interface TraceRow {
  id: string;
  timestamp: string | null;
  name: string | null;           // null is shown as a dash
  user_id: string | null;
  latency_ms: number | null;
  cost_usd: number;              // 0 means "not priced" and is shown as a dash, not as $0.00
  status?: string | null;        // shown as recorded, for example 'ok', 'client_error', 'error'
  total_tokens?: number | null;
}
```

## 7. `GET /agents/{id}/metrics` returns `AgentMetrics`

Query: `date_from: string`, `date_to: string` (`YYYY-MM-DD`, inclusive; default range is the
last 30 days).

```ts
interface MetricTotals { traces: number; cost_usd: number; tokens: number }
interface AgentMetrics {
  cost_available?: boolean;      // false: the source cannot price usage. Absent means true.
  warnings?: string[];           // short, safe notes about gaps in the data; shown above the charts
  totals: MetricTotals;
  daily: { date: string; traces: number; cost_usd: number; tokens: number }[];   // date is YYYY-MM-DD; rows outside the range are dropped
  by_model: { model: string; cost_usd: number; tokens: number }[];
  by_user: { user_id: string; cost_usd: number; traces: number }[];              // may be []
}
```

The Cost tab renders entirely from this endpoint. All-zero `totals` with empty lists renders the
"No cost data in this window" state.

When `cost_available` is `false`, every cost figure is displayed as "Not available" (never as
`$0.00`), a notice says so, and the model breakdown is drawn by tokens instead of cost. The same
applies to endpoint 18.

## 8. `GET /agents/{id}/evals/runs` returns `EvalRuns`

```ts
interface EvalRuns {
  runs: EvalRun[];                     // newest first; the first 10 are displayed
  overrides: PromoteOverride[];        // the first 10 are displayed
  current_digest: string | null;       // image digest of the current build ("sha256:<64 hex>")
  current_build_tag?: string | null;   // used when current_digest is null
  current_run: EvalRun | null;         // the latest run for the current build
  warnings?: string[];                 // short, safe notes; shown above the gate card
}
interface EvalRun {
  run_id: string;
  repo_id: string;                     // not displayed
  agent_id: string;                    // not displayed
  project_id: string;                  // not displayed
  stage: string;                       // environment
  git_sha?: string | null;
  item_count?: number | null;
  digest?: string | null;
  build_tag?: string | null;
  trigger: 'manual' | 'auto';
  started_by: string;                  // not displayed
  started_at: string;
  finished_at?: string | null;         // not displayed
  status: 'running' | 'passed' | 'failed' | 'error';
  config: EvalConfig;
  summary?: EvalRunSummary | null;
  gate?: { passed: boolean; reasons: string[] } | null;
  baseline?: { run_id: string; build: string; checks_passed: number; checks_total: number; judge_mean: number | null } | null; // not displayed
  regressions?: string[];
}
interface EvalConfig {
  version: 1;
  dataset: string;
  checks: { tools: 'exact' | 'in_order' | 'any_order' | 'off'; args: 'exact' | 'subset' | 'off'; no_error: boolean };
  judges: string[];
  gate: { checks: 'all_pass'; judge_min_mean: number };   // judge_min_mean is the threshold shown next to judge means
}
interface EvalRunSummary {
  items: number;
  checks_passed: number;
  checks_failed: number;
  judge_means: Record<string, number | null>;   // judge id -> mean, null when not scored
}
interface PromoteOverride {
  repo_id: string;
  digest: string | null;
  build_tag?: string | null;
  by: string;                 // displayed when by_name is absent
  by_name?: string | null;
  reason: string;
  at: string;
}
```

How the gate card is derived for the current build (`current_digest || current_build_tag`):

- no current build: "No build to evaluate yet";
- `current_run` is null: "Not evaluated yet";
- `current_run.status` is `running`: "Evaluating" (or "The last run stopped responding" when it
  started more than two hours ago);
- otherwise "Release gate passed" **only if `current_run.gate.passed === true`**; any other
  finished run is "Release gate failed", with `gate.reasons` and `regressions` listed.

Only `config.gate.judge_min_mean` is read from `config`; a run without `config` is tolerated.

## 9. `GET /agents/{id}/mcp-grants` returns `AgentMcpGrant[]`

The tool gateways the agent is subscribed to.

```ts
interface AgentMcpGrant {
  mcp_id: string;       // McpServer.id; compared with Agent.declared_mcp_server_ids
  mcp_name: string;
  role: string;         // displayed as recorded
  assignment_id: string; // not displayed
}
```

Each row is displayed as "Subscribed". An id in `declared_mcp_server_ids` with no row here is
displayed as "Declared, not subscribed"; a row whose `mcp_id` is not declared (when the agent
declares at least one gateway) as "Subscribed, not declared".

## 10. `GET /mcp-servers` returns `McpServer[]`

Query: `lifecycle_state?: LifecycleState`. Displayed as "Tool gateways".

## 11. `GET /mcp-servers/{id}` returns `McpServer`

```ts
interface McpTool {
  name: string;
  description?: string;
  input_schema: Record<string, unknown>;   // displayed as formatted JSON
}
interface McpServer {
  id: string;
  name: string;
  description?: string;
  kind: McpServerKind;                     // 'gateway' shows the Policies tab
  owner_oid?: string | null;               // not displayed
  owner_email?: string | null;
  business_unit?: string | null;
  region?: string | null;
  data_classification?: DataClassification | null;
  endpoint_url?: string | null;            // displayed; falls back to gateway_url
  version: string;
  available_tools: McpTool[];
  gateway_arn?: string | null;
  project_id?: string | null;              // not displayed
  repo_id?: string | null;                 // not displayed
  cedar_policy_engine_id?: string | null;
  cedar_policy_engine_arn?: string | null; // not displayed
  cedar_enforcement_mode?: CedarEnforcementMode;   // list column and Overview; see endpoint 13
  entra_app_id?: string | null;            // not displayed
  entra_sp_id?: string | null;             // not displayed
  entra_app_audience?: string | null;      // not displayed
  invoker_role_id?: string | null;         // not displayed
  admin_role_id?: string | null;           // not displayed
  gateway_id?: string | null;              // not displayed
  gateway_url?: string | null;
  runtime_arn?: string | null;
  identity_status: IdentityStatus;
  lifecycle_state: LifecycleState;
  tenant_id?: string | null;
  shared?: boolean;                        // true is displayed as "Shared with all tenants"
  created_at: string;
  updated_at: string;
  created_by?: string | null;
}
```

## 12. `GET /mcp-servers/{id}/policies` returns `CedarPolicySet`

```ts
interface CedarPolicySet {
  enforcement_mode: CedarEnforcementMode;
  engine_id?: string | null;       // not displayed
  policies: CedarPolicyRow[];
  warnings?: string[];             // short, safe notes; shown above the policy list
}
interface CedarPolicyRow {
  policy_id: string;
  user_oid?: string | null;        // displayed when user_label is absent
  user_label?: string | null;      // principal; absent is displayed as "Any authorised caller"
  tool?: string | null;            // absent is displayed as "All tools"
  effect: string;                  // 'deny' or 'forbid' is displayed as "Forbid"; anything else as "Permit"
  conditions?: { param: string; op: string; value: string; type: string }[];   // only the count is displayed
  managed?: boolean;               // not displayed
  cedar_text: string;              // displayed verbatim on request
  kind?: 'contain' | null;         // not displayed
  agent_app_id?: string | null;    // not displayed
}
```

In the default profile a tool gateway authorises the calling workload with AWS IAM and there are
no per-end-user grants, so `user_oid` and `user_label` are expected to be empty.

## 13. `GET /mcp-servers/{id}/policy-enforcement` returns `CedarEnforcement`

```ts
interface CedarEnforcement {
  enforcement_mode: CedarEnforcementMode;
}
```

Drives the enforcement banner on the Policies tab. The front end uses, in order: this response,
`CedarPolicySet.enforcement_mode`, then `McpServer.cedar_enforcement_mode`. The three should
agree. (The upstream console only wrote to this path; the read is new.)

## 14. `GET /mcp-servers/{id}/grants` returns `Grant[]`

The agents subscribed to the gateway ("Connected agents").

```ts
interface Grant {
  assignment_id: string;
  principal_id: string;          // linked to an agent when it equals Agent.id or Agent.entra_sp_id
  principal_display: string;     // displayed; falls back to principal_id
  principal_type: 'User' | 'Group' | 'ServicePrincipal';   // not displayed
  role: 'Invoker' | 'Admin';     // displayed as recorded
}
```

## 15. `GET /governance-graph` returns `GovernanceGraph`

```ts
interface GovernanceGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
interface GraphNode {
  type: 'user' | 'group' | 'agent' | 'mcp';
  id: string;                    // unique within the graph; referenced by edges
  label: string;
  ref_id: string;                // agent: Agent.id; mcp: McpServer.id; user or group: the id for endpoint 16
  metadata: Record<string, unknown>;
}
interface GraphEdge {
  id: string;
  source: string;                // GraphNode.id
  target: string;                // GraphNode.id
  type: 'access' | 'can_call';   // access: principal -> agent; can_call: agent -> tool gateway
  role: string;
  has_policy?: boolean;          // true draws the edge as policy-governed; selecting it calls endpoint 12 for the target gateway
}
```

`metadata` keys read (all optional strings): for `agent` nodes `origin`, `lifecycle_state`,
`identity_status`, `platform`; for `mcp` nodes `kind`, `cedar_enforcement_mode`,
`identity_status`. In the default profile no `user` or `group` node has an edge to an `mcp`
node. An empty graph (`nodes: []`) renders an empty state.

## 16. `GET /principals/{id}` returns `PrincipalDetail`

Query: `kind: 'user' | 'group'`. `{id}` is the `ref_id` of a `user` or `group` graph node. A 404
(for example for `kind=user` in a deployment that has no user directory) is shown as "Could not
load directory detail".

```ts
interface PrincipalDetail {
  id: string;
  display_name: string;
  kind: 'user' | 'group';
  user_principal_name?: string | null;
  mail?: string | null;
  job_title?: string | null;
  group_names?: string[];
}
```

Note: the upstream console called this at `/governance-graph/principals/{id}`. The portal calls
`/principals/{id}`.

## 17. `GET /observability/settings` returns `ObservabilitySettings`

```ts
interface ObservabilitySettings {
  configured: boolean;   // false renders "Observability not configured" and endpoint 18 is not called
}
```

A failed request is treated as `configured: false`. Any other field in the response is not
read and may be omitted or null.

## 18. `GET /observability/metrics` returns `ScopeMetrics`

Query: `scope: 'platform' | 'tenant'`, `date_from: string`, `date_to: string` (`YYYY-MM-DD`,
inclusive). `scope` is always sent. `tenant` means the caller's own tenants. The front end sends `platform` only when
`CurrentUser.role_level >= 2`; the API must enforce that itself and answer 403 otherwise.

```ts
interface ScopeMetrics extends AgentMetrics {   // see endpoint 7
  by_agent: {
    agent_id: string;
    agent_name: string;
    tenant_id: string | null;
    totals: MetricTotals;
  }[];
}
```

`by_user` is not displayed on this screen.

## 19. `GET /guardrails` returns `GuardrailTemplate[]`

Displayed as "Guardrail profiles". Rows with `status: 'deleted'` are hidden. The list may return
summaries with empty configuration arrays: the list shows only `name`, `description` and `status`,
and the configuration is read from endpoint 20.

## 20. `GET /guardrails/{id}` returns `GuardrailTemplate`

`{id}` is `GuardrailTemplate.template_id`. Called when a profile is expanded.

```ts
type GuardrailFilterStrength = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
type GuardrailFilterType = 'HATE' | 'INSULTS' | 'SEXUAL' | 'VIOLENCE' | 'MISCONDUCT' | 'PROMPT_ATTACK';
type GuardrailPiiAction = 'BLOCK' | 'ANONYMIZE';
type GuardrailStatus = 'draft' | 'creating' | 'active' | 'updating' | 'failed' | 'deleting' | 'deleted';

interface GuardrailTemplate {
  template_id: string;
  name: string;
  description?: string;
  status: GuardrailStatus;
  guardrail_id?: string;             // not displayed
  guardrail_arn?: string;
  guardrail_version?: string;
  content_filters: { type: GuardrailFilterType; input_strength: GuardrailFilterStrength; output_strength: GuardrailFilterStrength }[];
  denied_topics: { name: string; definition: string; examples: string[] }[];          // names displayed
  pii_entities: { type: string; action: GuardrailPiiAction }[];
  sensitive_regexes: { name: string; pattern: string; description?: string; action: GuardrailPiiAction }[];   // names displayed; patterns are not
  word_filter?: { enable_profanity: boolean; blocked_words: string[] };               // the count of blocked words is displayed, not the words
  contextual_grounding?: { enabled: boolean; grounding_threshold: number; relevance_threshold: number };
  status_history: { status: string; timestamp: string; message?: string }[];          // not displayed
  created_by?: string;               // not displayed
  created_at: string;                // not displayed
  updated_at: string;
}
```

The list arrays (`content_filters`, `denied_topics`, `pii_entities`, `sensitive_regexes`) may be
empty but should be present.

## 21. `GET /fleet/health` returns `FleetHealth` (new)

Health of every Workstream cell: one agent in one environment.

```ts
type CellHealthState = 'healthy' | 'needs_attention' | 'critical' | 'no_data';

interface FleetHealth {
  checked_at: string;
  cells: FleetCell[];
  totals: FleetTotals;
}
interface FleetCell {
  tenant_id: string;
  agent_id: string;        // the agent's id in the cell configuration; shown as the label when agent_ref is absent
  agent_ref?: string | null; // Agent.id; when present the row links to that agent and shows its name
  environment: string;     // for example "nonprod" or "prod"
  account_alias: string;   // a display alias, never an account id
  region: string;
  state: CellHealthState;
  alarms_in_alarm: number; // displayed only when reachable is true
  reachable: boolean;      // false: the cell's telemetry could not be read; state should be 'no_data'
  detail?: string | null;  // optional short, safe explanation; shown as a tooltip on the state
}
type FleetTotals = Record<CellHealthState, number>;   // { healthy, needs_attention, critical, no_data }
```

`totals` must contain all four state counts as numbers; further counters are ignored. If any of
the four is missing, the front end counts `cells` itself. `(tenant_id, agent_id, environment)`
must be unique per cell. A `state` the front end does not recognise is displayed as "No data".

## 22. `GET /catalog/models` returns `CatalogModel[]` (new)

```ts
interface CatalogModel {
  model_id: string;      // unique; displayed in a monospace font
  provider: string;
  regions: string[];     // AWS Region codes
  status: string;        // displayed as recorded; 'approved', 'active', 'restricted', 'pending', 'deprecated', 'blocked' get a colour
}
```

## 23. `GET /catalog/tools` returns `CatalogTool[]` (new)

Tool records from the registry.

```ts
interface CatalogTool {
  tool_id: string;                 // unique
  name: string;
  description?: string | null;
  owner?: string | null;
  cost_centre?: string | null;
  status: string;                  // displayed as recorded; same colours as CatalogModel.status
  version?: string | null;
  target_arn?: string | null;      // displayed with the account id masked; the copy button copies the full value
}
```

## Governed registration and approval (only with `features.governedActions: true`)

The endpoints, bodies, status codes and rules are defined by the back end in
[`../api/ACTIONS_CONTRACT.md`](../api/ACTIONS_CONTRACT.md). This section lists exactly what the
front end calls and reads. The client is `src/actions/registrationsClient.ts`, the only module
that issues a write; it is loaded only when the flag is on.

| # | Method | Path | Body | Response |
|---|--------|------|------|----------|
| 24 | GET | `/registrations` | query `status?` | `Registration[]` |
| 25 | GET | `/registrations/{record_id}` | none | `RegistrationDetail` |
| 26 | GET | `/registrations/{record_id}/history` | none | `RegistrationHistory` |
| 27 | POST | `/registrations` | `RegistrationInput` | `ActionResult` |
| 28 | PUT | `/registrations/{record_id}` | `RegistrationInput` | `ActionResult` |
| 29 | POST | `/registrations/{record_id}/submit` | none | `ActionResult` |
| 30 | DELETE | `/registrations/{record_id}` | none | `ActionResult` |
| 31 | POST | `/registrations/{record_id}/approve` | `{ reason, document_sha256 }` | `ActionResult` |
| 32 | POST | `/registrations/{record_id}/reject` | `{ reason, document_sha256 }` | `ActionResult` |

Which screen calls what:

| Screen | Endpoints |
|--------|-----------|
| Registrations (list) | 24 with `status` when a filter is chosen |
| Register agent (new) | 23 (tools to choose from), 3 when opened from a discovered agent, then 27 |
| Edit registration | 25, 23, then 28 |
| Registration (record page) | 25, 26; then 29, 30, 31 or 32 on the matching action |
| Approvals | 24 with `status=PENDING_APPROVAL`, then 25 once per pending record |

What the front end reads and sends:

```ts
interface Registration {
  record_id: string;
  name: string;                    // shown when agent_id is absent
  status: string;                  // registry status; an unknown value is shown as recorded
  status_reason?: string | null;   // shown as the decision when decision_reason is absent
  record_version?: string | null;
  tenant_id?: string | null;
  agent_id?: string | null;
  environment?: string | null;
  document: RegistrationDocument;  // snake_case keys; see ACTIONS_CONTRACT.md
  document_sha256: string;         // sent back with a decision
  created_at?: string | null;
  updated_at?: string | null;
}

interface RegistrationDetail extends Registration {
  created_by_label?: string | null;
  submitted_by_label?: string | null;
  submitted_at?: string | null;
  submitted_by_me?: boolean;       // true hides Approve and Reject and explains why
  decision?: string | null;        // not displayed
  decided_by_label?: string | null;
  decided_at?: string | null;
  decision_reason?: string | null;
  previous_approved?: RegistrationDocument | null;   // the document at the latest approval made through the portal; null when there was none
}

interface RegistrationHistory {
  record_id: string;
  events: {
    event_id: string; request_id: string; at: string;
    phase: 'intent' | 'result'; action: string; outcome: 'allowed' | 'denied' | 'failed';
    reason: string; actor_label: string; actor_role?: string | null;
    status_before?: string | null; status_after?: string | null;
  }[];
}

interface ActionResult {
  action: string; outcome: string; reason: string;
  request_id: string;              // shown as the reference when audit_complete is false
  registration: Registration | null;
  audit_complete: boolean;         // false is shown as a warning
}
```

- **Form fields** (the document's properties): tenant, agent id, environment, owner group,
  contact, business purpose, risk class, data classification, cost centre, application id,
  framework, golden path name and version, runtime ARN, tool gateway ARN, subscribed tool ids,
  record version. Other properties of an existing document (`memory_id`, `policy_engine_arn`,
  `policy_engine_mode`, `source_revision`, `evaluation`) are sent back unchanged on an update.
- **Request body** of 27 and 28: the flat `RegistrationInput`, snake_case, without
  `schema_version`. An empty optional field is omitted, never sent as an empty string. On an
  update `record_version` is omitted unless the user raised it.
- **Client-side validation** copies the enums, patterns, lengths and required fields of
  `packages/agent-registry/schemas/agent-governance-1.0.json`. A test reads that file and fails
  if the copy drifts. The server's answer always wins.
- **Locked inputs:** tenant, agent id and environment on any existing record; runtime ARN, tool
  gateway ARN, subscribed tools, risk class and data classification on an `APPROVED` record,
  with the explanation that changing them needs a new registration.
- **Controls offered:** Edit on `DRAFT`, `PENDING_APPROVAL`, `REJECTED`, `APPROVED` (with a
  warning that saving returns the record to Draft); Submit on `DRAFT`; Delete on anything except
  `APPROVED`; Approve and Reject on `PENDING_APPROVAL` when `can_approve` is true and
  `submitted_by_me` is not true. Nothing is offered on a record whose tenant is outside a
  restricted `registration_tenants`.
- **History:** one row per action, taken from the `result` events. An `intent` with no `result`
  is kept and marked "No result recorded". A 404 is shown as "no history".
- **Errors:** a 422 is a list of `{ loc, msg, type }` and is mapped to form fields by the name
  after `"body"` in `loc` (`risk_class`, or `golden_path` then `name`); an item that names no
  form field is shown above the form; 403 is shown as "You do not hold the
  authority for this action" with `detail`; 409 as a state conflict with `detail` and a Refresh
  button (this also covers the second or so a record spends in `CREATING` or `UPDATING`); 503
  as "Nothing was changed", with an invitation to try again. `hint` and `request_id` are shown
  when present.

**Diff.** When `previous_approved` is present, the record page shows the fields that differ
between it and `document`. `record_version` is left out, since the server raises it on every
update. An optional field that was not sent again is shown as "Removed". When
`previous_approved` is null (a record never approved through the portal) no diff is shown. On
an unchanged `APPROVED` record the two are equal and the section is hidden; on a
`PENDING_APPROVAL` record with no differences it says so.

## Runtime configuration and sign-in (what infrastructure must provide)

The site must serve `/config.json` next to the bundle:

```json
{
  "apiBaseUrl": "https://<api-host>/api/v1",
  "authProvider": "cognito",
  "cognito": {
    "authority": "https://cognito-idp.<region>.amazonaws.com/<userPoolId>",
    "clientId": "<appClientId>",
    "domain": "https://<prefix>.auth.<region>.amazoncognito.com",
    "scopes": ["openid", "email", "profile"]
  },
  "entra": {
    "tenantId": "<tenantId>",
    "clientId": "<spaClientId>",
    "apiScope": "api://<apiAppId>/access_as_user"
  },
  "environment": "nonprod",
  "features": { "readOnly": true, "governedActions": false }
}
```

- `apiBaseUrl` is an `https` URL or a same-origin path such as `/api/v1` (`http` is accepted for
  `localhost` only). A trailing slash is removed.
- Only the block named by `authProvider` is required and validated. A value that is empty,
  still contains `<` or `>`, or is an all-zero GUID is rejected and the portal shows a
  configuration error page instead of starting.
- `cognito.scopes` defaults to `["openid", "email", "profile"]` and must include `openid`.
- `environment` is `nonprod` (default) or `prod`. `features.readOnly` defaults to `true` and is
  informational.
- `features.governedActions` defaults to `false`. Only the boolean `true` turns it on. Off, the
  registration screens, routes, navigation entries and their code are absent and the site issues
  only `GET` requests. On, a Content Security Policy needs nothing new (`connect-src` already
  covers the API), but CORS on the action endpoints must allow `POST`, `PUT`, `DELETE` and the
  `content-type` request header.
- Serve `/config.json` with `Cache-Control: no-cache`; the front end also requests it with
  `cache: 'no-store'`.
- The host must answer unknown paths with `index.html` (single-page application routing).

Identity provider registration:

| | Amazon Cognito | Microsoft Entra ID |
|---|---|---|
| Flow | Authorization code with PKCE, public client (no client secret) | Authorization code with PKCE (MSAL), single-page application |
| Redirect (callback) URL | `https://<site>/auth/callback` | `https://<site>/auth/callback` |
| Sign-out URL | `https://<site>/` (sent as `logout_uri` to `<domain>/logout?client_id=…&logout_uri=…`) | `https://<site>` (post-logout redirect) |
| Scopes | `cognito.scopes` | `entra.apiScope` |
| Token sent to the API | ID token | access token |
| Session renewal | refresh token, on demand | silent renewal by MSAL |

For Cognito, the user pool's OIDC discovery document
(`<authority>/.well-known/openid-configuration`) and token endpoint are called from the browser,
so a Content Security Policy must allow `connect-src` for the `cognito-idp` endpoint, the hosted
UI domain and the API. The `cognito:groups` claim is read for display only.
