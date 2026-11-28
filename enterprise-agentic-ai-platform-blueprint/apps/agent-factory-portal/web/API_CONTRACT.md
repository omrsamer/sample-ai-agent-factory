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
- **503 when the caller cannot be verified.** The API verifies the caller's token in its
  functions as well as at its gateway. When the identity provider's signing keys cannot be
  fetched, any endpoint answers 503 with a sentence in `detail` and nothing was read or done.
  A page shows that sentence in its error state with Retry, like any failed read, and an
  action shows it under "Nothing was changed". Two limits: the export (endpoint 37) and the
  evidence document (endpoint 41) ask for a file, so their error body is not read and the
  page names the status only; and if the read of `/users/me` fails when the app starts, the
  session has no roles until the page is loaded again.
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
| 36 | GET | `/fleet/summary` | none | `FleetSummary` |
| 37 | GET | `/agents/export` | `format` | a file (`text/csv` or `application/json`) |
| 38 | GET | `/omni/observed-services` | `hours` | `ObservedServices` |
| 41 | GET | `/agents/{id}/evidence` | none | a file (`application/json`) |

Endpoints 1 to 20 keep the wire shapes of the upstream console the portal is derived from.
Endpoints 21 to 23, 36 to 38 and 41 are new in the portal. Endpoints 24 to 35 belong to the governed
actions feature and are listed in their own sections.

Which screen calls what:

| Screen | Endpoints |
|--------|-----------|
| Every screen (profile in the sidebar) | 1 |
| Fleet | 2, 10, 21, 36, 38 |
| Agents (list) | 2; 37 when Export is used |
| Agent detail: Overview | 3 |
| Agent detail: Tool subscriptions | 9 |
| Agent detail: Deployment | 4, 5 |
| Agent detail: Traces | 6 |
| Agent detail: Cost | 7 |
| Agent detail: Release evidence | 8 |
| Agent detail: "Download evidence" (every tab) | 41 when the button is used |
| Tool gateways (list) | 10 |
| Tool gateway detail: Overview, Tools | 11 |
| Tool gateway detail: Policies | 12, 13 (not for a gateway no reader read) |
| Tool gateway detail: Connected agents | 14, 2 (not for a gateway no reader read) |
| Access graph | 15, 16 (a user or group node is selected), 12 (a policy edge is selected) |
| Observability | 17, 18, 2 |
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
type AuthType = string;            // 'none' | 'aws_iam' | 'custom_jwt'; shown only when inbound_authorizer is absent
type IdentityStatus = 'none' | 'pending' | 'provisioned' | 'failed';
type McpServerKind = 'gateway' | 'standard' | 'runtime';
type CedarEnforcementMode = 'none' | 'log_only' | 'enforce';   // the modes that are worded; 'unknown' and anything else read "Enforcement mode unknown"
```

The front end tolerates values outside these unions: an unknown lifecycle state, platform,
runtime status, deployment outcome, guardrail status or catalog status is displayed as recorded,
and an unknown Cedar enforcement mode is displayed as "Enforcement mode unknown". It never
assumes "healthy", "ready" or "enforcing" for a value it does not recognise.

`auth_type` is displayed only when `inbound_authorizer` is absent: `none` "None recorded",
`aws_iam` "AWS IAM (SigV4)", `custom_jwt` "JSON Web Token (custom authorizer)", `api_key`
"API key"; any other value is shown as recorded. `inbound_authorizer` is displayed as `AWS_IAM`
"AWS IAM (SigV4)", `CUSTOM_JWT` "JSON Web Token (custom authorizer)", `NONE` "None:
unauthenticated calls are accepted"; any other value as recorded.

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
  can_contain?: boolean;   // governed actions only: may contain an agent
  can_release?: boolean;   // governed actions only: may release one, unless they contained it
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

`can_register`, `can_approve`, `can_contain`, `can_release` and `registration_tenants` only
decide which controls are offered. Only the boolean `true` grants an authority. The action endpoints enforce every rule
themselves, and a refusal is displayed.

`registration_tenants` is also the caller's own tenants for the "My tenants" switch on the
agents list. The switch is shown only when the list is not empty and does not hold `"*"`: a
caller who holds every tenant, or for whom the API sends `null`, has nothing to narrow. It is
off by default, is remembered for the browser session, and keeps the agents whose `tenant_id`
is in the list. It works with the feature flag on or off. `tenants` is not used for this: it
lists every tenant of the fleet, for showing names.

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
  sponsor_email?: string | null;      // not displayed
  business_unit?: string | null;      // not displayed
  region?: string | null;             // shown under the account
  data_classification?: DataClassification | null;
  platform?: Platform | null;
  framework?: string | null;
  mcp_server_ids: string[];           // not displayed directly; see endpoint 9
  declared_mcp_server_ids?: string[]; // tool gateways the agent descriptor declares
  origin: Origin;                     // 'Deployed' shows the Deployment tab
  identity_status: IdentityStatus;    // displayed as "Workload identity"
  lifecycle_state: LifecycleState;
  endpoint_url?: string | null;
  auth_type: AuthType;
  agent_arn?: string | null;          // runtime ARN of the most recently deployed environment
  agent_arns?: Record<string, string> | null; // environment -> runtime ARN; keys feed the environment selector
  runtime_handle?: string | null;     // shown when agent_arn is absent
  runtime_kind?: string | null;       // not displayed
  tenant_id?: string | null;
  registration?: string | null;       // 'registered' | 'discovered'; decides whether a contain names the runtime
  inventory_state?: string | null;    // 'registered_and_detected' | 'detected_only' | 'registered_only'
  detection_sources?: string[] | null; // 'cell_reader' "Cell reader", 'organization_registry' "Organization registry"; others as recorded
  flags?: AgentFlags | null;
  risk?: AgentRisk | null;
  obligations_closed?: boolean | null; // true: a retired registration with nothing deployed; see below
  governance?: AgentGovernance | null; // null for an agent that is only detected
  sponsor?: string | null;             // read before governance.sponsor
  review_by?: string | null;           // the effective review date (the latest attestation, else the document's); read before governance.review_by
  last_reviewed_at?: string | null;    // "Last reviewed", for a registered agent; null reads "Not reviewed yet"
  last_reviewed_by?: string | null;    // follows the time: "<time> by <label>"
  account_alias?: string | null;       // shown as "Account" when present
  reader_status?: string | null;       // 'ok' | 'unreachable' | 'none'; see below
  registry_status?: string | null;     // not displayed
  environment?: string | null;         // not displayed here
  inbound_authorizer?: string | null;  // 'AWS_IAM' | 'CUSTOM_JWT' | 'NONE'; shown instead of auth_type when present
  last_invoked_on?: string | null;
  omni_url?: string | null;            // https only; opened in a new tab
  created_at: string;
  updated_at: string;
  created_by?: string | null;
}

interface AgentFlags {                 // true, false, or null when it could not be evaluated
  unmanaged?: boolean | null;
  ownerless?: boolean | null;
  review_overdue?: boolean | null;
  inactive?: boolean | null;
  contained?: boolean | null;
}
interface AgentRisk {
  level: string;                       // 'critical' | 'high' | 'medium' | 'low'
  reasons: { code: string; severity: string; detail: string }[];
}
interface AgentGovernance {            // the fields the read screens show
  owner_group?: string | null;         // the accountable owner
  contact?: string | null;
  sponsor?: string | null;             // the accountable person; optional
  review_by?: string | null;           // YYYY-MM-DD
  risk_class?: string | null;          // not displayed
  cost_centre?: string | null;         // not displayed
}
```

How the inventory fields are displayed:

- **`inventory_state`**: `registered_and_detected` "Registered"; `detected_only` "Not
  registered"; `registered_only` "Registered, not running". Absent is "State unknown"; any other
  value is shown as recorded. The lifecycle is shown for a registered agent only.
- **`lifecycle_state: "deprecated"`** is shown as "Retired" (badge, filter option, fleet tile).
  On the agent page of a retired registration whose risk reasons hold
  `REGISTRATION_DEPRECATED`, a callout shows that reason's `detail` and what is left to do: the
  runtime must be removed by its pipeline, and the portal removes nothing that is deployed.
- **`flags`**, as chips next to an agent:
  - `ownerless`, `review_overdue` and `inactive` are shown by name when `true`.
  - `unmanaged` is never a chip, because the state and the lifecycle already say it. It is a
    filter ("No approved registration").
  - `contained: true` is the "Contained" badge, wherever the agent appears: the agents list, the
    agent page, the fleet "Needs attention" list, fleet health rows, a tool gateway's connected
    agents, the Observability by-agent table, the release evidence picker, and the access graph
    (see 15).
  - A `null` flag is never treated as `false`. What is shown for it depends on why it is null.
    `reader_status: "none"` shows one chip, "No reader role in this account", and no other;
    `"unreachable"` shows one chip, "Reader role unreachable". Otherwise `contained` and
    `inactive` show "Containment unknown" and "Activity unknown" for an agent that is running,
    and `ownerless` and `review_overdue` show as unknown only for a registered agent: ownership
    and review do not apply to an agent with no registration, and activity and containment do
    not apply to one that is not running.
  - When `flags` itself is null nothing is shown.
- **`risk`**: the level is always shown in words ("High risk"). Absent `risk` is "Risk not
  assessed", never "low". On the agent page each reason is listed with its severity, its
  `detail` sentence and its `code`; a reason with an empty `detail` shows the code spelled out.
- **`obligations_closed: true`** (a retired registration with nothing deployed; only the
  boolean `true` counts). No risk rule applies and the flags `unmanaged`, `ownerless`,
  `review_overdue` and `inactive` are null because they do not apply. Such an agent is shown as
  retired, with no risk badge and no flag chip of any kind, and none of its null flags is
  worded as unknown or not readable. In the agents list its Risk cell reads "Not applicable".
  On its page the retired callout reads that nothing is deployed and nothing is left to do,
  the risk section reads "This registration is retired and nothing is deployed, so no risk
  rule applies.", a missing owner group is stated without a warning, and "Last invoked" reads
  "Not applicable". The filters "Containment not readable" and "Activity not readable" do not
  list it, and neither does any risk filter. `/fleet/summary` counts it under
  `by_risk_level.low`; the fleet page takes such agents out of the "Low risk" tile (it has the
  agents from endpoint 2), so that the tile and the list it links to agree. It is never in the
  fleet's "Needs attention" list.
- **Ownership card**: owner group, sponsor, contact, review date (`review_by`, the effective
  date) and, for a registered agent, when and by whom it was last reviewed. The owner group is the
  accountable owner. When the agent is flagged `ownerless` the field shows the `detail` of the
  risk reason `OWNERLESS` or `OWNER_GROUP_NOT_IN_ROSTER` under the value. The sponsor is
  optional: its absence reads "None recorded" and nothing more. An agent with no registration
  reads "None recorded (no registration)" for both. `business_unit` is not displayed.
- **`reader_status: "none"`** on an agent that names a runtime: the Tool subscriptions (for an
  agent with no registration), Deployment, Traces and Cost tabs show "No reader role in this
  account" with one sentence, and endpoints 4 to 7 and 9 are not called for that agent. The
  Containment tab reads "Not readable" and endpoint 33 is not called. Release evidence still
  calls endpoint 8 and shows its `warnings` as plain sentences when there is no run.
- **Account**: shown as `account_alias`, else as the account id masked to its last four digits
  (from `account_id`, else from the ARN). No page shows an account id in full: `created_by`,
  caller ids in traces and usage, changed values in a registration diff and Cedar policy text
  are masked the same way. `created_by` is shown as the agent's `account_alias` when it equals
  the agent's `account_id`.
- **Names**: an agent name wraps only at hyphens, underscores and spaces. Where a name stands
  alone (fleet "Needs attention", observed agents, a gateway's connected agents, the release
  evidence picker, the containment confirmation, the agent page header) the tenant and the
  account follow it, because two agents can carry one name.
- **Empty values** are written in words ("None", "Not set", "Not recorded"), never as a dash.
- **Empty answers with notes**: when traces or metrics come back empty together with
  `warnings`, the notes are shown and the page says "No traces to show", not "No traces
  recorded yet". The same holds for the Cost tab and the Observability page.
- **Filters** on the agents list run in the browser on these fields, and are kept in the
  address as `?flag=`, `?risk=`, `?state=`, `?lifecycle=` and `?account=` so the fleet tiles
  can link to a filtered list. `flag=contained:unknown` and `flag=inactive:unknown` list agents
  for which that could not be read; `risk=none` those with no `risk`; `lifecycle=awaiting`
  every registered agent that is not approved; `account=` an alias or a masked id. The
  `lifecycle_state` query parameter of endpoint 2 is no longer sent. `/agents` must therefore
  return these fields for every agent in one response.
- **Columns** of the agents list: Agent, State, Risk, Flags, Tenant, Account (with the Region
  under it), Lifecycle. Below 1280 px the tenant is written under the account and the lifecycle
  under the state.

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

No query parameter is sent. Displayed as "Tool gateways". The list is searched (by name or by
the account as shown) and filtered (every gateway, those a reader read, those no reader read)
in the browser, so the response must hold every gateway.

Columns: Tool gateway, Tenant, Account (alias, else the id masked to its last four digits,
with the Region under it), Tools, Policy, State. `kind` and `owner_email` are no longer shown:
the API sends one kind and no owner.

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
  owner_email?: string | null;             // not displayed
  business_unit?: string | null;           // not displayed
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
  cedar_enforcement_mode?: string;         // 'none' | 'log_only' | 'enforce' | 'unknown'; list column and Overview; see endpoint 13
  gateway_id?: string | null;              // not displayed
  gateway_url?: string | null;
  runtime_arn?: string | null;
  identity_status: IdentityStatus;
  lifecycle_state: LifecycleState;
  tenant_id?: string | null;
  shared?: boolean;                        // true is displayed as "Shared with all tenants"
  created_at: string;                      // the epoch is shown as "Not recorded", never as a date
  updated_at: string;
  created_by?: string | null;
  account_id?: string | null;              // shown masked, when account_alias is absent
  account_alias?: string | null;           // shown as "Account"
  environment?: string | null;             // not displayed
  authorizer_type?: string | null;         // "Inbound authorizer": 'AWS_IAM' | 'CUSTOM_JWT' | 'NONE'; others as recorded
  protocol?: string | null;                // "Protocol", as recorded
  detection_sources?: string[] | null;     // "Detected by": 'cell_reader', 'organization_registry'
  reader_status?: string | null;           // 'ok' | 'none' | 'unreachable' | 'not_listed'; absent is read as 'ok'
  detail?: string | null;                  // for a gateway no reader read: the reason, shown as sent
}
```

**A gateway no reader read** (`reader_status` other than `ok`; a value this build does not
know counts as not read). The organization registry detected it and nothing of its tools, its
tenant, its policy engine or its policies is known. None of that is shown as "none":

- **List.** A chip under the name ("No reader role in this account", "Reader role unreachable",
  "Not listed by the reader"), "Not readable" for Tenant, Tools and Policy, the account and
  Region, and the state "Not managed here" (`reader_status: "none"`) or "Detected only" (the
  other reasons). A sentence above the list counts these gateways.
- **Gateway page.** The header shows the account and Region, the same state and the chip, and
  no version. The Overview shows `detail` as sent (the page's own sentence when it is absent)
  and "What was detected": the ARN (account masked), account, Region, what detected it, the
  inbound authorizer, the protocol and the detection time. A value the detection does not
  carry reads "Not recorded". No description, endpoint, tenant, policy engine or data
  classification is shown.
- **Tools, Policies and Connected agents** each show the same title and sentence instead of an
  empty list, and **endpoints 12, 13 and 14 are not called** for such a gateway. Connected
  agents adds that an agent whose registration names the gateway lists it under its own Tool
  subscriptions (endpoint 9).

For a gateway a reader read the Overview also shows the account, what detected it, the inbound
authorizer and the protocol when they are sent.

## 12. `GET /mcp-servers/{id}/policies` returns `CedarPolicySet`

```ts
interface CedarPolicySet {
  enforcement_mode: string;        // 'none' | 'log_only' | 'enforce' | 'unknown'
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
  enforcement_mode: string;        // 'none' | 'log_only' | 'enforce' | 'unknown'
  detail?: string | null;          // why the mode is unknown; shown in the banner
}
```

Drives the enforcement banner on the Policies tab. The front end uses, in order: this response,
`CedarPolicySet.enforcement_mode`, then `McpServer.cedar_enforcement_mode`. The three should
agree. (The upstream console only wrote to this path; the read is new.)

A mode other than `none`, `log_only` or `enforce` is shown as "Enforcement mode unknown", with
`detail` when it is sent, and an empty policy list then reads "The policies of this gateway
could not be read.", not "No Cedar policy is attached". For a gateway no reader read the tab
does not call endpoints 12 and 13 at all (see 11).

## 14. `GET /mcp-servers/{id}/grants` returns `Grant[]`

The agents subscribed to the gateway ("Connected agents").

```ts
interface Grant {
  assignment_id: string;
  principal_id: string;          // linked to an agent when it equals Agent.id
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

`metadata` keys read (all optional): for `agent` nodes `origin`, `lifecycle_state`,
`identity_status`, `platform`; for `mcp` nodes `kind`, `enforcement_mode` (the older
`cedar_enforcement_mode` is still read), `tool_count`, `reader_status`, `identity_status`. In
the default profile no `user` or `group` node has an edge to an `mcp` node. An empty graph
(`nodes: []`) renders an empty state.

An `mcp` node whose `reader_status` is not `ok` is a gateway no reader read. It is drawn with a
dashed outline and the marker "Not read", and its detail panel reads "Reader: No reader role
in this account" (or the other reason), "Cedar enforcement: Not readable", "Tools: Not
readable", and says that no connection to it is drawn because who can call it is not known.

The graph does not say whether an agent is contained, nor which account it is in. The page
therefore also reads endpoint 2 and joins it to the `agent` nodes by `ref_id` = `Agent.id`: an
agent whose `flags.contained` is `true` is marked "Contained" in the drawing, the table view
and the detail panel, and each agent node carries its tenant and account, because two agents
can carry one name. `metadata.contained: true` on a node is honoured too. If endpoint 2 fails
the graph is still drawn, without those two additions.

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
  omni_url?: string | null;  // https only; "Open in Omni" on the row
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

## 36. `GET /fleet/summary` returns `FleetSummary` (new)

```ts
interface FleetSummary {
  generated_at?: string | null;                    // not displayed
  agents_total: number;
  by_inventory_state?: Record<string, number> | null;   // keys as Agent.inventory_state
  by_lifecycle?: Record<string, number> | null;         // 'approved', 'rejected' and 'deprecated' feed the first row of tiles
  by_risk_level?: Record<string, number> | null;        // 'critical' | 'high' | 'medium' | 'low'
  flags?: Record<string, number> | null;                // per flag: agents that have it set
  flags_unknown?: Record<string, number> | null;        // per flag: agents for which it is unknown
  gateways_total?: number | null;                       // "N tool gateways serve these agents"
  gateways_by_policy_mode?: Record<string, number> | null;   // 'enforce' | 'log_only' | 'none' | 'unknown'; added to that sentence
  organization_registry?: string | null;                // 'ok', 'disabled', or an error code
  unreachable_cells?: number | null;
  inactive_days?: number | null;
  omni_url?: string | null;                             // not displayed
  omni_domains?: { account_alias: string; region?: string | null; url?: string | null }[] | null;   // not displayed
  needs_attention?: unknown[] | null;                   // not read; see below
  review_attestations?: string | null;                  // 'ok', 'disabled', or an error code; see below
  warnings?: string[] | null;
}
```

Tiles, each linking to the agents list filtered to what it counts.

The first row is a partition that adds up to the total: Agents (`agents_total`), Approved
(`by_lifecycle.approved`, zero when the key is absent), Awaiting approval (the total minus
Approved, Not registered and Retired: every registration that is neither approved nor retired,
with the number of rejected ones named in the hint when there are any), Not registered
(`by_inventory_state.detected_only`) and, only when it is not zero, Retired
(`by_lifecycle.deprecated`).

The second row is what needs attention: Contained, Ownerless, Review overdue, Inactive (from
`flags`), and Registered, not running (`by_inventory_state.registered_only`) only when it is
not zero. Then one tile per risk level. A count that is missing is shown as "Unknown", never as
zero. When `flags_unknown.contained` or `flags_unknown.inactive` is above zero that tile also
shows "N not readable", linking to those agents. `flags_unknown.ownerless` and
`flags_unknown.review_overdue` are not shown: they count agents with no registration, for which
ownership and review do not apply. Every entry of `warnings` is shown as a note above the
tiles, as sent. Only when `warnings` is empty are `unreachable_cells` above zero and an
`organization_registry` other than `ok` or `disabled` put into words by the page, so nothing is
said twice. Whenever either holds, one sentence adds that the counts may be incomplete.

The tile hints follow the API's definitions: Ownerless "No owner group, or one that is not in
the owner roster."; Inactive "No invocation in N days." from `inactive_days`.

Under the tiles one sentence counts the tool gateways from `gateways_total` and
`gateways_by_policy_mode`, for example "3 tool gateways serve these agents: 1 enforcing policy,
2 only logging policy decisions." The fleet page no longer calls endpoint 10 for this. When
`unknown` is above zero (gateways no reader read) the sentence reads "12 tool gateways are
known: 1 enforcing policy, 2 only logging policy decisions, 9 whose policy cannot be read.":
such a gateway is never counted as having no policy engine, and is not said to serve these
agents.

The "Needs attention" list is computed in the browser from endpoint 2, not from
`needs_attention`: every agent at critical or high risk, and every agent that is contained,
ownerless or overdue for review, most severe first, with its tenant and account and its risk
reasons. A registration that only waits for approval is not listed for that alone.

The fleet health table names its first column "Cell": a cell need not hold an agent.

The Retired tile links to the agents list filtered to `lifecycle=deprecated`.
`review_attestations` other than `ok` or `disabled` is put into words only when `warnings` is
empty: the counts stand, and every review date shown is then the registration's own.

## 37. `GET /agents/export` returns a file (new)

Query: `format: 'csv' | 'json'`. The response is fetched with the bearer token (a token cannot
be put in a link) and saved by the browser. The file name is read from
`Content-Disposition`; cross-origin, that needs
`Access-Control-Expose-Headers: Content-Disposition`. Only the base name is used, and
characters outside letters, digits, dot, underscore, hyphen and space are replaced. Without a
readable name the file is saved as `agents.csv` or `agents.json`.

## 38. `GET /omni/observed-services` returns `ObservedServices` (new)

```ts
interface ObservedServices {
  checked_at?: string | null;       // not displayed
  window_hours?: number | null;     // "over the last N hours"
  services: ObservedService[];      // agents only
  omni_url?: string | null;         // one "Open in CloudWatch Omni" link for the section
  domains?: { account_alias: string; region?: string | null; url?: string | null }[] | null;
                                    // "Observed by CloudWatch Omni in <region> of <account_alias>."
  warnings?: string[] | null;       // shown above the table
}
interface ObservedService {
  name: string;
  node_type?: string | null;        // not displayed
  category?: string | null;         // always GEN_AI_AGENT; not displayed
  resource_id?: string | null;      // not displayed
  runtime_arn?: string | null;      // not displayed
  region?: string | null;
  last_observed_at?: string | null; // null is shown as a dash
  signals?: string[] | null;
  registered?: boolean;             // true: "Registered agent"
  detected?: boolean;               // true and not registered: "Detected, not registered"
  matched_agent_id?: string | null; // Agent.id; links to the agent
  inventory_state?: string | null;  // not read: registered and detected decide the label
  omni_region?: string | null;      // not displayed per row; the section names the domains
  account_alias?: string | null;    // not displayed per row
}
```

An agent that is neither `registered` nor `detected` (`inventory_state: "observed_only"`) is
marked "Observed in telemetry only". A null `last_observed_at` reads "Not observed". The
request is sent with `hours` (24, 72 or 168, chosen in the page: 24 hours, 3 days, 7 days) and
without `cell`. An empty list reads "No agent was observed by CloudWatch Omni in the last 24
hours." A warning of the form "<account>: skipped, Omni is read only in the portal's own
account." is not shown as a warning: those accounts are named in one muted line under the list
("Not read: <accounts>. Omni can be read only in the portal's own account."). Every other
warning is shown above the list.

**CloudWatch Omni links.** `omni_url` on an agent (shown next to Traces), on a fleet cell row
and on `ObservedServices` is rendered as a link that opens a new tab with
`rel="noopener noreferrer"`, and only when it is an absolute `https` URL. Nothing is embedded.

## 41. `GET /agents/{id}/evidence` returns a file (new)

One JSON document about one agent, for an auditor. The agent page offers "Download evidence" to
every role, with the feature flag on or off. Like the inventory export it is fetched with the
bearer token and saved by the browser under the name in `Content-Disposition` (cross-origin,
the header must be exposed); without a readable name the file is saved as
`agent-evidence.json`. The document is not parsed or previewed.

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
| 39 | POST | `/registrations/{record_id}/retire` | `{ reason }` | `ActionResult` |
| 40 | POST | `/registrations/{record_id}/review` | `{ reason, next_review_by }` | `ActionResult` |

Which screen calls what:

| Screen | Endpoints |
|--------|-----------|
| Registrations (list) | 24 with `status` when a filter is chosen |
| Register agent (new) | 23 (tools to choose from), 3 when opened from a discovered agent, then 27 |
| Edit registration | 25, 23, then 28 |
| Registration (record page) | 25, 26; then 29, 30, 31, 32, 39 or 40 on the matching action |
| Agent page of a registered agent (the Registration panel) | 25; then 39 or 40, and 25 again |
| Approvals | 24 with `status=PENDING_APPROVAL`, then 25 once per pending record |

What the front end reads and sends:

```ts
interface Registration {
  record_id: string;
  name: string;                    // shown when agent_id is absent
  status: string;                  // registry status; an unknown value is shown as recorded. DEPRECATED is shown as "Retired"
  lifecycle_state?: string;        // not displayed: the label comes from status
  status_reason?: string | null;   // shown as the decision when decision_reason is absent, and as the reason of a retirement
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
  last_reviewed_at?: string | null;    // "Last reviewed": the latest review or approval (every approval records a review date)
  last_reviewed_by?: string | null;
  effective_review_by?: string | null; // "Review due"; falls back to document.review_by
}

interface RegistrationHistory {
  record_id: string;
  events_truncated?: boolean;      // true: the API listed the newest events only
  events: {
    event_id: string; request_id: string; at: string;
    phase: 'intent' | 'result'; action: string; outcome: 'allowed' | 'denied' | 'failed' | 'unchanged';
    reason: string; actor_label: string; actor_role?: string | null;
    status_before?: string | null; status_after?: string | null;
    next_review_by?: string | null;  // shown under the action of a review and of an approval (every approval records a review date)
    attested_at?: string | null;     // not displayed
    detail?: string | null;          // not displayed
  }[];
}

interface ActionResult {
  action: string;
  outcome: string;                 // 'unchanged': the retire of a record that was already retired
  reason: string;                  // shown after a retire: the server's sentence about what retirement means
  request_id: string;              // shown as the reference when audit_complete is false
  registration: Registration | null;
  audit_complete: boolean;         // false is shown as a warning
}
```

- **Form fields** (the document's properties): tenant, agent id, environment, owner group,
  sponsor, review date (`review_by`, a date input limited to 366 days ahead in UTC, which the
  form also checks before sending; a past date is allowed), contact, business purpose, risk class, data classification, cost centre, application id,
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
  `APPROVED` (so also on a retired record); Approve and Reject on `PENDING_APPROVAL` when
  `can_approve` is true and `submitted_by_me` is not true. Nothing is offered on a record whose
  tenant is outside a restricted `registration_tenants`. Review and retirement are described
  below.
- **History:** one row per action, taken from the `result` events. An `intent` with no `result`
  of the same request and the same action is kept and marked "No result recorded". A 404 is
  shown as "no history". When `events_truncated` is true a line under the table reads "Only the
  newest entries are listed. Older entries exist and are not shown here.".
- **Errors:** a 422 is a list of `{ loc, msg, type }` and is mapped to form fields by the name
  after `"body"` in `loc` (`risk_class`, or `golden_path` then `name`); an item that names no
  form field is shown above the form (for example `policy_engine_arn`, which the form carries
  through unchanged and has no field for, when it begins with another partition than its
  cell's; the same refusal for `runtime_arn` or `gateway_arn` is shown at that field); 403 is
  shown as "You do not hold the authority for this action" with `detail`; 409 as a state
  conflict with `detail` and a Refresh
  button (this also covers the second or so a record spends in `CREATING` or `UPDATING`); 503
  as "Nothing was changed", with an invitation to try again. `hint` and `request_id` are shown
  when present. `request_id` is shown as "Reference:" and nothing more: the API keeps a refusal
  in the history only when the caller has a part in the record or the runtime, and in its log
  otherwise, and the page does not know which.

**Diff.** When `previous_approved` is present, the record page shows the fields that differ
between it and `document`. `record_version` is left out, since the server raises it on every
update. An optional field that was not sent again is shown as "Removed". When
`previous_approved` is null (a record never approved through the portal) no diff is shown. On
an unchanged `APPROVED` record the two are equal and the section is hidden; on a
`PENDING_APPROVAL` record with no differences it says so.

### After approval: review and retirement (endpoints 39 and 40)

Both are in `src/actions/registrationsClient.ts` and are offered on the registration page and,
for a registered agent, in a "Registration" panel on the agent page (a registered agent's `id`
is its `record_id`). They use the approver authority: `can_approve` and a `registration_tenants`
that holds the record's tenant or `"*"`. Retire has no two-person rule. A review cannot be
confirmed by the registration's submitter (`submitted_by_me`), and only once in 24 hours.

Read from `RegistrationDetail` (endpoint 25): `status`, `status_reason`, `effective_review_by`,
`last_reviewed_at`, `last_reviewed_by`, and `document.review_by` as the fallback date.

- **Status wording.** `DEPRECATED` is shown as "Retired" everywhere (registration status,
  agent `lifecycle_state: "deprecated"`, filters, history). The word "Deprecated" is not used.
- **The document's own review date.** The "Governance document" section shows `document.review_by`
  under "Review by", and "Not set" when the document names none. It does not say that the
  registration has no review date: every approval records one, and the date in force is the
  one under "Review due".
- **Periodic review**, on an `APPROVED` registration: "Review due" (`effective_review_by`,
  else `document.review_by`), "Review overdue" when that date is before today in UTC, and "Last
  reviewed" (`last_reviewed_at` by `last_reviewed_by`, else "Not reviewed yet"). "Confirm
  review" opens a form with the next review date and a reason. The date input is limited to
  tomorrow through today plus 366 days, counted in UTC, and defaults to today plus 180 days. The
  form checks the same rules as the server before sending. A 422 whose `loc` names
  `next_review_by` or `reason` is shown at that field (for example `REV-04-N`); 403 and 409 are
  shown with `detail` and `request_id`. After a 200 endpoint 25 and the history are read again.
- **When a review would be refused** "Confirm review" is shown disabled with the reason beside
  it, not hidden and not a button that fails on click. For the submitter (`submitted_by_me`
  true, `REV-05-N`): "You submitted this registration, so you cannot confirm its review.
  Another approver must." Right after a review made on the page (`REV-06-N`): "Its review was
  confirmed just now. Another one can be recorded after 24 hours." The page keeps that only
  until it is left: `last_reviewed_at` does not say whether the latest attestation was a
  review or an approval, so after a reload the button is enabled and the server's refusal is
  shown if it is used too early.
- **Retire**, on every registration that is not `DEPRECATED`: a destructive button. The
  confirmation says "Retiring is permanent: the registration cannot be approved, changed or
  submitted again. To bring the agent back, register it again." and "The runtime keeps running
  until its pipeline removes it. Retiring removes nothing that is deployed." The button is
  disabled until a reason is entered. After a 200 with `outcome: "allowed"` the page shows
  `reason` as sent (the server's sentence); with `outcome: "unchanged"` it shows "The
  registration was already retired. Nothing was changed."
- **A retired registration** shows a "Retired" panel that says why nothing can be done, with
  `status_reason`, and offers no approve, reject, edit, submit, review or retire. Delete is
  still offered to a registrar.
- **History** (endpoint 26): `retire` is labelled "Retire" and `review` "Confirm review". An
  event's `next_review_by` is shown under the action ("Next review by 2027-05-27"), for a
  review and for an approval. Every approval records a review date: the one the document
  names, or the approval date plus 366 days when it names a later one or none. The page reads
  the date from the API and does not compute it. A refusal of the same person by the same
  rule is listed once while the record stays as it is, however often it was repeated, and so
  is the `unchanged` result of a retirement asked for again; each answer still carries its
  own `request_id`, which the page shows as the reference.
- **One more read after an action.** What an action changes elsewhere on the agent (its risk
  and reasons, `obligations_closed`) is assessed by the API only once its cache of the agent
  has expired. After a review, a retirement, a contain or a release made on the agent page,
  the page therefore reads endpoint 3 once more, 35 seconds later. That read is silent: if it
  fails nothing changes on screen. The fields the action settled keep being shown as verified;
  of the flags only those the action settled are overridden, the others follow the API.
- **On the agent page** the review date, "Last reviewed" and the lifecycle come from endpoint 3
  (`review_by`, `last_reviewed_at`, `last_reviewed_by`, `lifecycle_state`), which the API serves
  from a short cache. After a review or a retirement made on that page, endpoint 25 is read
  again (the API reads a registration fresh) and the header and the ownership card show its
  facts until the page is left: `effective_review_by`, `last_reviewed_at`, `last_reviewed_by`
  as recorded, "Review overdue" by the same rule as the API, and "Retired". The page does not
  put the caller's display name there, because the API records a person by an identifier they
  cannot change. If that read fails, the page shows the date it sent and names no reviewer.
  After a refusal on that page endpoint 25 is read again as well.
- With the feature off none of this is offered, endpoint 25 is not called, and the agent page
  shows "Review by" and "Last reviewed" read-only.

## Containment (only with `features.governedActions: true`)

Defined by the back end in [`../api/CONTAINMENT_CONTRACT.md`](../api/CONTAINMENT_CONTRACT.md).
The client is `src/actions/containmentClient.ts`, loaded only when the flag is on. With the flag
off the agent page has no Containment tab and none of these endpoints is called; the
"Contained" badge is still shown, because it comes from `flags.contained` on endpoint 2.

| # | Method | Path | Body | Response |
|---|--------|------|------|----------|
| 33 | GET | `/agents/{id}/containment` | none | `ContainmentView` |
| 34 | POST | `/agents/{id}/containment/contain` | `{ reason, runtime_arn? }` | `ContainmentResult` |
| 35 | POST | `/agents/{id}/containment/release` | `{ reason, runtime_arn? }` | `ContainmentResult` |

What the front end reads:

```ts
interface ContainmentView {
  agent_id: string;
  state: string;                    // 'contained' | 'not_contained' | 'unknown'; anything else is treated as unknown
  runtime_arn?: string | null;      // null: "No runtime to contain"; otherwise not displayed
  enabled?: boolean;                // false: no action is offered, with the reason
  detail?: string | null;           // why the state is unknown; with a known state, a note shown as sent (see below)
  contained_by_label?: string | null;   // incident record: sent only to a role that can contain or release
  contained_at?: string | null;     // sent to every role
  reason?: string | null;           // incident record
  contained_by_me?: boolean;        // true: Release is not offered, with the reason
  partial?: boolean;                // true: says not every session was stopped, until quiet_at is set
  enforcement_delay_seconds?: number | null;   // contain: "within about 90 seconds"; 90 when absent
  release_delay_seconds?: number | null;       // release: "for about 5 minutes"; 300 when absent
  sweeps?: { scheduled?: number | null; done?: number | null } | null;   // "Background sweeps: 1 of 2 done."
  quiet_at?: string | null;         // "No running session since <time>."
  events?: AuditEvent[] | null;     // incident record: one row per action and per background sweep
  events_truncated?: boolean;       // true: a line under the history says that older entries are not listed
}
interface ContainmentResult {
  action: string; outcome: string;  // outcome 'unchanged': see below
  request_id: string;
  state: string;                    // the headline claims containment or release only when this confirms it
  steps?: { id: string; label: string; status: string; detail?: string | null }[] | null;   // listed with status in words
                                    // id 'background' with status 'scheduled' or 'failed': the sweeps a contain leaves behind
  sessions?: {
    discovery: string;              // 'ok' | 'ok; <what was incomplete>' | why nothing was listed or stopped
    sources?: { spans?: number; log_streams?: number } | null;   // only the sources that are present are named
    found?: number; stopped?: number; not_active?: number; failed?: number; not_attempted?: number;
    stop_errors?: string[] | null;
  } | null;
  policy_deleted?: boolean; other_statements_kept?: number; denied_actions?: string[] | null;   // not displayed: the steps say it
  replaced_foreign_statement?: boolean;   // not displayed: the policy step says it
  partial?: boolean;
  enforcement_delay_seconds?: number | null;
  sweeps_scheduled_in_seconds?: number[] | null;   // not displayed: the 'background' step says it
  retry_after_seconds?: number | null;   // contain, 'unchanged': it came too soon and did nothing; see "Stop remaining sessions"
  audit_complete?: boolean;         // false is shown as a warning with request_id
}
```

- **Who is offered what** (from `/users/me`): Contain when `can_contain` is true and the state
  is `not_contained`; Release when `can_release` is true, the state is `contained` and
  `contained_by_me` is not true. When `contained_by_me` is true and the caller holds
  `can_release`, Release is shown as a disabled button with "You contained this agent. A
  different person must release it." beside it. Nothing is offered when `enabled` is false or
  the state is unknown. Each case that is not offered says why. The tenant rule is not
  anticipated (the tenant is decided by where the runtime runs): a caller who holds the role
  but not the agent's tenant is offered the action and shown the server's refusal (`CON-04-N`,
  `CON-05-N`).
- **No reader role** (`Agent.reader_status: "none"`): the tab reads "Not readable. The portal
  has no role in this agent's account, so it cannot read its state or contain it." and calls
  nothing.
- **Unknown state.** The state card shows `detail` followed by "Whether the agent can be invoked
  is therefore not known." It is never shown as "Not contained". When `runtime_arn` is null the
  card reads "No runtime to contain" with `detail`. Under an unknown state the note reads "No
  action is offered while the containment state cannot be read." also when `enabled` is false
  (a registration that names its runtime by another spelling of its ARN): the note about the
  cell not having given the portal the authority is kept for a state that was read.
- **`detail` with a known state** is shown under the state, as sent: with `not_contained`, that
  a statement carrying the portal's identifier is in the policy and is not the one the portal
  writes, so it may or may not deny invocation (Contain is still offered, and replaces it);
  with `contained`, that who contained the agent could not be established. In the second case
  the page does not also say that the agent was contained by other means.
- **Confirmation.** Before sending, the page names the agent with its tenant and account, lists
  what will happen ("New invocations of this agent are denied. An occasional call can still get
  through for about 90 seconds.", from the view's `enforcement_delay_seconds`; running sessions
  are stopped; nothing is deleted; it is reversible by a different person) and requires a
  reason: the button is disabled until one is entered, for release as well. For a release it
  says "The agent can be invoked again. Some calls can still be refused for about 5 minutes
  while the change spreads.", from the view's `release_delay_seconds`. When the view carries
  no release delay the page uses 300 seconds, the measured value, and not the contain delay,
  which would promise a faster release than the service gives.
- **State card.** A contained agent reads "Contained" and "Invocations of this agent are
  denied. Nothing was deleted, and it can be released.". An agent that is not contained reads
  "Not contained" and "Invocations of this agent are not denied by the portal.". That is what
  the portal knows: its own statement is not in the policy. The page does not say that the
  agent can be invoked, because a statement in another shape, or one written by other means,
  may deny invocation.
- **Delays in words.** A delay below two minutes is given in seconds and a longer one in
  minutes. After an action the headline uses the result's `enforcement_delay_seconds`:
  "Contained. Invocations are blocked within about 90 seconds." and "Released. Some calls can
  still be refused for about 5 minutes." The page never says "now" and shows no spinner that
  waits for enforcement.
- **Recorded reasons** (`reason` on the view and on events) are shown in two parts: the text
  before the first " [" as the reason, and the bracketed text under it, smaller, without the
  brackets.
- **`runtime_arn`** is sent, from `Agent.agent_arn`, only for an agent with no registration:
  `Agent.registration` is `discovered` (or, when that field is absent, `governance` is null).
- **Partial results.** A result is shown as partial when `partial` is true, when a step's
  status is anything other than `done`, `unchanged`, `skipped` or `scheduled`, or when
  `sessions` reports a failure, sessions that were not attempted, or a `discovery` other than
  `ok`. The headline names what did not complete: "not every running session was stopped"
  (the `sessions` step or the counts), "the background sweeps could not all be scheduled" (the
  `background` step), or both. The steps are always listed with their `detail` sentences. The
  page writes its own sentence about the sessions (counts, where they were found, the stop
  errors, what was incomplete) only when the `sessions` step carries no `detail`.
- **`outcome: "unchanged"`.** For a contain: "The agent was already contained. Its policy was
  not changed." It does not say that nothing happened, because a repeated contain still stops
  the sessions it finds. For a release: "This agent was not contained by the portal. Nothing
  was changed." The API's step under it says what it found, for example that a statement with
  the portal's identifier is there in another shape.
  For the contain sent again by "Stop remaining sessions": "Sessions swept again.", followed
  by what did not complete when something did not.
- **Background sweeps.** A contain can leave sweeps on a queue that run after the request, for
  up to 15 minutes. The state card of a contained agent shows "Background sweeps: `done` of
  `scheduled` done." when `sweeps.scheduled` is above zero. Under it, a role that is sent the
  events sees each sweep of this containment (the `sweep` events at or after `contained_at`,
  oldest first) on one line: "Sweep 2, <time>: 3 checked, 0 stopped, 3 already ended, 0
  failed. Complete." from `sweep`, `at`, `sessions_found`, `sessions_stopped`,
  `sessions_not_active`, `sessions_failed` and `outcome` (`allowed` "Complete", `failed`
  "Incomplete", `skipped` "Skipped"). `sessions_found` is worded "checked": a sweep tries
  every session of the last eight hours, ended or not. While `done` is below `scheduled`
  the tab reads endpoint 33 again every 20 seconds (at most 120 times, and not while the page
  is hidden) and says so. Such a read uses GET only; one that fails changes nothing on screen
  and is tried again. If it finds a different `state` (someone released the agent), the tab
  and the page header follow it. Without sweeps (`scheduled` 0) the card says nothing about
  them and nothing is read again.
- **Quiet.** Once `quiet_at` is set the card reads "No running session since <time>. Every
  session the portal could find has ended or was stopped." and the partial warning is no
  longer shown, because `quiet_at` is the later and stronger statement. When every sweep has
  run and `quiet_at` is still null the card reads "Every background sweep has run, and none
  confirmed that no session is still running." When a sweep never reported (see "Stop
  remaining sessions") and `quiet_at` is still null, a role that is sent the events reads "A
  background sweep has still not reported 30 minutes after its contain, and none confirmed
  that no session is still running." A role that is not sent them is not told: the page would
  have to count from `contained_at`, and the sweeps of a later contain could still be due.
- **Quiet, and then a sweep that failed or never reported.** `quiet_at` is the first time the
  agent was known to be quiet (normally sweep 2) and the API keeps it for the whole
  containment. The sweep after it is there for a session that started late. When the newest
  sweep of the containment has outcome `failed`, or a sweep never reported, "No running
  session since" would say more than is known, so a role that is sent the events reads
  instead "A background sweep at <time> left no session running." and, under the sweeps,
  "The newest background sweep did not complete. A session that started later may still be
  running." or "A later background sweep has still not reported 30 minutes after its contain.
  A session that started later may still be running." A role that is not sent the events
  cannot tell and reads what `quiet_at` says.
- **Stop remaining sessions.** The API's remedy for sessions that may be left is to contain
  again. The tab shows "Stop remaining sessions" to a caller with `can_contain`, on a
  contained agent with `enabled` not false, in four cases. Two hold whatever `quiet_at`
  says: the newest sweep of this containment has outcome `failed`; or a sweep never reported
  (`sweeps.done` is still below `sweeps.scheduled` 30 minutes after the newest contain of
  this containment that did its work, which is when the API gives such a sweep up). Two hold
  only while `quiet_at` is null: `partial` is true; or at least one sweep was scheduled and
  every scheduled sweep has run. The contain that the 30 minutes are counted from is the
  newest `contain` result at or after `contained_at` with outcome `allowed` or `unchanged`
  and session counts; a contain that was answered at once carries no counts and does not
  move the time. Without such an event the time is counted from `contained_at`. The page's
  clock is read when the tab opens, at every re-read, when a confirmation opens and after an
  action; it is the browser's clock, so a clock that is behind shows the button later. It is
  also offered right after a contain on this page whose `background` step failed. The view
  does not show that afterwards (`partial` is about sessions only, and `sweeps.scheduled` is
  0 as in a portal without a sweep queue), so after a reload, or to another person, the
  button is not offered for that reason. It sends endpoint 34 with a reason, through a
  confirmation that says the agent stays contained, that its policy is not changed, and that
  who may release it does not change. It is shown to the person who contained the agent as
  well.
- **The button does not wait for the sweeps.** Whether `sweeps.done` is below
  `sweeps.scheduled` does not disable it: a sweep that was lost never reports, and the counts
  then stay "1 of 2 done" for good. The page does not guard against a contain that comes too
  soon either. The API answers that one at once and does nothing. The confirmation says so
  before a reason is asked for, when it can apply: "If the last contain was less than about 15
  minutes ago, or one of its background sweeps is still running, nothing more is done and the
  answer says when to ask again." That line is shown for a containment with sweeps
  (`sweeps.scheduled` above zero) while a sweep has yet to report and is not given up, or
  while the newest contain that did its work is less than 900 seconds old, and also when the
  page has no time to count from. The 900 seconds and the 30 minutes are the API's figures.
- **A contain that came too soon** (the answer carries `retry_after_seconds`): the headline
  reads "The agent was already contained. Nothing more was done.", the steps are listed with
  the API's sentence as sent (that the background sweeps are still running, or that they ran
  less than about 15 minutes ago, and when to ask again), and `sessions: null` is not read as
  a failure. The button is then shown disabled for that many seconds with "Sessions can be
  swept again in about N minutes." beside it (seconds below two minutes), not hidden and not
  a button that fails on click. The time is never more than 900 seconds. That is kept in the
  page only; after a reload the button is enabled again and a click gets the same answer with
  a shorter time. The request leaves one `result` row in the history for each person who
  asks ("Contain", "No change"), with no intent before it.
- **The incident record follows the caller's role.** The API sends `contained_by_label`,
  `reason` and `events` only to a role that can contain or release. A caller who holds neither
  `can_contain` nor `can_release`, and was sent none of them, sees "Contained since
  `contained_at`." and, under History, one muted line: "Who contained this agent, why, and the
  history are shown to the security, platform and SRE roles." No table and no "not recorded"
  is shown to them. The state, `partial`, the sweeps and `quiet_at` are shown
  to every role.
- **History rows.** One row per `result` event, and one for an `intent` that has no `result`
  of the same request and the same action. A background sweep (`action: "sweep"`) carries the
  request id of its contain and is a row of its own, labelled "Background sweep", with its
  actor as recorded ("Agent Factory Portal (background sweep)", role `system`). A sweep is not
  a person's decision, so its row is quieter: smaller, muted, and its outcome in words
  ("Complete", "Incomplete", "Skipped") instead of a coloured chip.
- **Errors.** 403, 409 and 503 as for registrations. 502 is shown as "The action failed
  part-way" with `detail`, the `steps` of the error body and `request_id`, and the state is
  read again.
- After every action, successful or not, endpoint 33 and the agent (endpoint 3) are read again.
- **The flag can lag.** `flags.contained` is served from the API's short cache, so the agent read
  right after an action can still carry the old value. On the agent page the "Contained" badge in
  the header therefore follows the `state` the action verified, until the page is left. The
  agents list, the fleet page and the other places that show the badge read `flags.contained`
  and can lag by the cache lifetime.

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
  registration screens, the Containment tab, their routes, navigation entries and code are
  absent and the site issues only `GET` requests. On, a Content Security Policy needs nothing new (`connect-src` already
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
