// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import {
  AUTH_401_COUNT_KEY,
  AUTH_401_HALT_MESSAGE,
  AUTH_401_RELOAD_MESSAGE,
  clearsAuth401Suspicion,
  decide401,
  readAttempts,
  safeStorage,
} from './authRetry';
import { currentBearerToken } from '../auth/tokenBroker';
import type {
  ApiError,
  ApiValidationErrorItem,
  GuardrailTemplate,
  ObservabilitySettings,
  AgentMetrics,
  ScopeMetrics,
  TraceRow,
} from '../types';

/**
 * Typed client for the Agent Factory Portal API.
 *
 * Milestone 1 is read-only: every call in this module is a GET. The full list, with the
 * response type of each endpoint, is in `API_CONTRACT.md`.
 *
 * Paths are relative to `apiBaseUrl` from the runtime configuration, which already ends in
 * `/api/v1`.
 */
const client = axios.create({
  // Set by `configureApiClient` before the first request. The default keeps tests and a
  // same-origin deployment working without configuration.
  baseURL: '/api/v1',
  headers: { Accept: 'application/json' },
});

/** Points the client at the API named by the runtime configuration. */
export function configureApiClient(apiBaseUrl: string): void {
  client.defaults.baseURL = apiBaseUrl;
}

type RetriableConfig = InternalAxiosRequestConfig & { _forceRefreshRetried?: boolean };

client.interceptors.request.use(async (config: RetriableConfig) => {
  // A retry already carries the force-refreshed token; do not replace it with a cached one.
  if (config._forceRefreshRetried) return config;
  const token = await currentBearerToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

/**
 * The 401 decision for this page load. A page usually fires several requests at once, so the
 * first 401 decides and the rest of the burst reuse its answer instead of each reading a
 * counter a sibling has just written.
 */
let latched401: 'reload' | 'halt' | null = null;

/**
 * Turns an error `detail` into readable text: a string passes through, a validation list is
 * joined as `field: message`, anything else falls back to the given message.
 */
export function formatApiErrorDetail(
  detail: ApiError['detail'] | undefined,
  fallback: string,
): string {
  if (typeof detail === 'string' && detail.length > 0) return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    return detail
      .map((item: ApiValidationErrorItem) => {
        const field = item.loc?.filter((p) => p !== 'body').pop();
        return field ? `${field}: ${item.msg}` : item.msg;
      })
      .join('; ');
  }
  return fallback;
}

/** Thrown for a non-2xx response, so callers can tell "not found" from other failures. */
export class ApiRequestError extends Error {
  readonly status: number | undefined;
  /** The `detail` of the error body as sent, for callers that map validation errors to fields. */
  readonly detail: ApiError['detail'] | undefined;
  /** The whole error body, for callers that read fields beyond `detail`. */
  readonly body: unknown;
  constructor(message: string, status: number | undefined, detail?: ApiError['detail'], body?: unknown) {
    super(message);
    this.name = 'ApiRequestError';
    this.status = status;
    this.detail = detail;
    this.body = body;
  }
}

export function isNotFound(err: unknown): boolean {
  return err instanceof ApiRequestError && err.status === 404;
}

client.interceptors.response.use(
  (response) => {
    if (clearsAuth401Suspicion(response.config.headers?.Authorization)) {
      safeStorage.remove(AUTH_401_COUNT_KEY);
    }
    return response;
  },
  async (error: AxiosError<ApiError>) => {
    if (error.response?.status === 401) {
      // One retry with a force-refreshed token, capped by a flag on the request.
      const config = error.config as RetriableConfig | undefined;
      if (config && !config._forceRefreshRetried) {
        const refreshed = await currentBearerToken({ forceRefresh: true });
        if (refreshed) {
          config._forceRefreshRetried = true;
          config.headers.Authorization = `Bearer ${refreshed}`;
          return client(config);
        }
      }
      if (latched401 === null) {
        const attempts = readAttempts(safeStorage.read(AUTH_401_COUNT_KEY));
        latched401 = decide401(attempts);
        if (latched401 === 'reload') {
          // Written before the navigation, which discards everything else on the page.
          safeStorage.write(AUTH_401_COUNT_KEY, String(attempts + 1));
          if (typeof window !== 'undefined') window.location.reload();
        }
      }
      const message = latched401 === 'halt' ? AUTH_401_HALT_MESSAGE : AUTH_401_RELOAD_MESSAGE;
      return Promise.reject(new ApiRequestError(message, 401));
    }
    const message = formatApiErrorDetail(error.response?.data?.detail, error.message);
    return Promise.reject(
      new ApiRequestError(message, error.response?.status, error.response?.data?.detail, error.response?.data),
    );
  },
);

export default client;

// --- Current user ----------------------------------------------------------

/** A Workstream tenant the caller belongs to. The UI reads `id` and `name`. */
export interface UserTenant {
  id: string;
  name: string;
  line_of_business: string;
  stages: Record<string, unknown>;
}

/** `GET /users/me`. The back end decides the role; the UI only displays it. */
export interface CurrentUser {
  email: string;
  role: string;
  /** 0 viewer, 1 operator, 2 admin. Milestone 1 uses it only to pick the default metrics scope. */
  role_level: number;
  can_deploy: boolean;
  oid: string | null;
  name: string | null;
  /** Label to show for the caller (name, then email). Never the token subject. */
  display_name?: string | null;
  /** May create, edit, submit and delete registrations. The action endpoints enforce it. */
  can_register?: boolean;
  /** May approve and reject registrations. The action endpoints enforce it. */
  can_approve?: boolean;
  /** Tenants the caller acts for: `["*"]` for every tenant, null when not known. */
  registration_tenants?: string[] | null;
  tenants: UserTenant[];
}

export const userApi = {
  getCurrentUser: async (): Promise<CurrentUser> => (await client.get<CurrentUser>('/users/me')).data,
};

// --- Agents ------------------------------------------------------------------

/** `discovered` marks a runtime found in a cell that has no registry record. */
export type LifecycleState = 'proposed' | 'pending_approval' | 'approved' | 'rejected' | 'deprecated' | 'discovered';
/** Hosting platform key. `aws_bedrock` for Workstream cells; other values render verbatim. */
export type Platform = string;
export type DataClassification = 'Public' | 'Internal' | 'Confidential' | 'Restricted';
export type Origin = 'Deployed' | 'Registered';
export type AuthType = 'none' | 'entra' | 'api_key';
export type IdentityStatus = 'none' | 'pending' | 'provisioned' | 'failed';

/** `GET /agents` (array) and `GET /agents/{id}`. */
export interface Agent {
  id: string;
  /** Display name. For a registered agent this is its agent id. */
  name: string;
  /** Name of the agent's record in the registry. Null or absent for a discovered agent. */
  record_name?: string | null;
  purpose?: string;
  sponsor_oid?: string | null;
  sponsor_email?: string | null;
  business_unit?: string | null;
  region?: string | null;
  data_classification?: DataClassification | null;
  platform?: Platform | null;
  framework?: string | null;
  /** Tool gateways the agent is subscribed to. */
  mcp_server_ids: string[];
  /** Tool gateways the agent's descriptor declares; compared with its subscriptions. */
  declared_mcp_server_ids?: string[];
  origin: Origin;
  entra_app_id?: string | null;
  entra_api_app_id?: string | null;
  entra_sp_id?: string | null;
  entra_app_audience?: string | null;
  invoker_role_id?: string | null;
  admin_role_id?: string | null;
  identity_status: IdentityStatus;
  lifecycle_state: LifecycleState;
  endpoint_url?: string | null;
  auth_type: AuthType;
  /** Runtime ARN of the most recently deployed environment. */
  agent_arn?: string | null;
  /** Every runtime the agent owns, as `environment -> ARN`. */
  agent_arns?: Record<string, string> | null;
  runtime_handle?: string | null;
  runtime_kind?: string | null;
  tenant_id?: string | null;
  created_at: string;
  updated_at: string;
  created_by?: string | null;
}

/** Server-side filter. Search and the other filters are applied in the browser. */
export interface AgentListFilters {
  lifecycle_state?: LifecycleState;
}

export const agentsApi = {
  list: async (filters?: AgentListFilters): Promise<Agent[]> =>
    (await client.get<Agent[]>('/agents', { params: filters })).data,
  get: async (id: string): Promise<Agent> =>
    (await client.get<Agent>(`/agents/${encodeURIComponent(id)}`)).data,
};

// --- Runtime status, deployment history, release evidence --------------------

/** `GET /agents/{id}/runtime`. */
export interface RuntimeStatus {
  agent_id: string;
  /** The environment this reading describes. */
  stage: string;
  /** Free-form status word; narrow it with `runtimeStatusBadge` before display. */
  status: string;
  runtime_arn?: string | null;
  image_tag?: string | null;
  checked_at: string;
  /** A short, safe hint. Never an ARN, a token or a response body. */
  detail?: string | null;
}

export type DeploymentOutcome = 'started' | 'succeeded' | 'failed';

/** One row of `GET /agents/{id}/deployments`: one attempt to put one image on one environment. */
export interface Deployment {
  id: string;
  repo_id: string;
  agent_id?: string | null;
  mcp_server_id?: string | null;
  stage: string;
  seq_key: string;
  image_tag: string;
  source_sha?: string | null;
  build_id?: string | null;
  outcome: DeploymentOutcome;
  actor?: string | null;
  actor_kind?: string | null;
  started_at: string;
  completed_at?: string | null;
  error?: string | null;
}

export type ToolMatch = 'exact' | 'in_order' | 'any_order' | 'off';
export type ArgsMatch = 'exact' | 'subset' | 'off';

export interface EvalConfig {
  version: 1;
  dataset: string;
  checks: { tools: ToolMatch; args: ArgsMatch; no_error: boolean };
  judges: string[];
  gate: { checks: 'all_pass'; judge_min_mean: number };
}

export type EvalRunStatus = 'running' | 'passed' | 'failed' | 'error';

export interface EvalRunSummary {
  items: number;
  checks_passed: number;
  checks_failed: number;
  judge_means: Record<string, number | null>;
}

export interface EvalRun {
  run_id: string;
  repo_id: string;
  agent_id: string;
  project_id: string;
  stage: string;
  git_sha?: string | null;
  item_count?: number | null;
  digest?: string | null;
  build_tag?: string | null;
  trigger: 'manual' | 'auto';
  started_by: string;
  started_at: string;
  finished_at?: string | null;
  status: EvalRunStatus;
  config: EvalConfig;
  summary?: EvalRunSummary | null;
  gate?: { passed: boolean; reasons: string[] } | null;
  baseline?: { run_id: string; build: string; checks_passed: number; checks_total: number; judge_mean: number | null } | null;
  regressions?: string[];
}

/** A promotion made without a passing evaluation, with the reason recorded. */
export interface PromoteOverride {
  repo_id: string;
  digest: string | null;
  build_tag?: string | null;
  by: string;
  by_name?: string | null;
  reason: string;
  at: string;
}

/** `GET /agents/{id}/evals/runs`. */
export interface EvalRuns {
  runs: EvalRun[];
  overrides: PromoteOverride[];
  current_digest: string | null;
  current_build_tag?: string | null;
  current_run: EvalRun | null;
  /** Short, safe notes about gaps in the evidence. */
  warnings?: string[];
}

export const agentOpsApi = {
  runtime: async (agentId: string, params?: { stage?: string }): Promise<RuntimeStatus> =>
    (await client.get<RuntimeStatus>(`/agents/${encodeURIComponent(agentId)}/runtime`, {
      params: { stage: params?.stage },
    })).data,
  /** Newest first. `stage` omitted means every environment. */
  deployments: async (
    agentId: string,
    params?: { stage?: string; limit?: number },
  ): Promise<Deployment[]> =>
    (await client.get<Deployment[]>(`/agents/${encodeURIComponent(agentId)}/deployments`, {
      params: { stage: params?.stage, limit: params?.limit },
    })).data,
  evalRuns: async (agentId: string): Promise<EvalRuns> =>
    (await client.get<EvalRuns>(`/agents/${encodeURIComponent(agentId)}/evals/runs`)).data,
};

// --- Tool gateways (wire name: MCP servers) -----------------------------------

export type McpServerKind = 'gateway' | 'standard' | 'runtime';

export interface McpTool {
  name: string;
  description?: string;
  input_schema: Record<string, unknown>;
}

export type CedarEnforcementMode = 'none' | 'log_only' | 'enforce';

export interface CedarCondition {
  param: string;
  op: string;
  value: string;
  type: string;
}

export interface CedarPolicyRow {
  policy_id: string;
  /** Principal the policy names. Empty in the default profile, where callers are IAM roles. */
  user_oid?: string | null;
  user_label?: string | null;
  /** Tool the policy covers; null or absent means every tool. */
  tool?: string | null;
  /** `allow` or `deny`. */
  effect: string;
  conditions?: CedarCondition[];
  /** True when the row was generated by tooling rather than authored as Cedar text. */
  managed?: boolean;
  cedar_text: string;
  kind?: 'contain' | null;
  agent_app_id?: string | null;
}

/** `GET /mcp-servers/{id}/policies`. */
export interface CedarPolicySet {
  enforcement_mode: CedarEnforcementMode;
  engine_id?: string | null;
  policies: CedarPolicyRow[];
  /** Short, safe notes about gaps in the policy read. */
  warnings?: string[];
}

/** `GET /mcp-servers/{id}/policy-enforcement`. */
export interface CedarEnforcement {
  enforcement_mode: CedarEnforcementMode;
}

/** `GET /mcp-servers` (array) and `GET /mcp-servers/{id}`. */
export interface McpServer {
  id: string;
  name: string;
  description?: string;
  kind: McpServerKind;
  owner_oid?: string | null;
  owner_email?: string | null;
  business_unit?: string | null;
  region?: string | null;
  data_classification?: DataClassification | null;
  endpoint_url?: string | null;
  version: string;
  available_tools: McpTool[];
  gateway_arn?: string | null;
  project_id?: string | null;
  repo_id?: string | null;
  cedar_policy_engine_id?: string | null;
  cedar_policy_engine_arn?: string | null;
  cedar_enforcement_mode?: CedarEnforcementMode;
  entra_app_id?: string | null;
  entra_sp_id?: string | null;
  entra_app_audience?: string | null;
  invoker_role_id?: string | null;
  admin_role_id?: string | null;
  gateway_id?: string | null;
  gateway_url?: string | null;
  runtime_arn?: string | null;
  identity_status: IdentityStatus;
  lifecycle_state: LifecycleState;
  tenant_id?: string | null;
  /** True when every tenant may subscribe to this gateway. */
  shared?: boolean;
  created_at: string;
  updated_at: string;
  created_by?: string | null;
}

export interface McpServerListFilters {
  lifecycle_state?: LifecycleState;
}

/** One row of `GET /mcp-servers/{id}/grants`: an agent connected to the gateway. */
export interface Grant {
  assignment_id: string;
  principal_id: string;
  principal_display: string;
  principal_type: 'User' | 'Group' | 'ServicePrincipal';
  role: 'Invoker' | 'Admin';
}

export const mcpServersApi = {
  list: async (filters?: McpServerListFilters): Promise<McpServer[]> =>
    (await client.get<McpServer[]>('/mcp-servers', { params: filters })).data,
  get: async (id: string): Promise<McpServer> =>
    (await client.get<McpServer>(`/mcp-servers/${encodeURIComponent(id)}`)).data,
  policies: async (id: string): Promise<CedarPolicySet> =>
    (await client.get<CedarPolicySet>(`/mcp-servers/${encodeURIComponent(id)}/policies`)).data,
  policyEnforcement: async (id: string): Promise<CedarEnforcement> =>
    (await client.get<CedarEnforcement>(`/mcp-servers/${encodeURIComponent(id)}/policy-enforcement`)).data,
  connectedAgents: async (id: string): Promise<Grant[]> =>
    (await client.get<Grant[]>(`/mcp-servers/${encodeURIComponent(id)}/grants`)).data,
};

/** One row of `GET /agents/{id}/mcp-grants`: a tool gateway the agent is subscribed to. */
export interface AgentMcpGrant {
  mcp_id: string;
  mcp_name: string;
  role: string;
  assignment_id: string;
}

export const agentMcpGrantsApi = {
  list: async (agentId: string): Promise<AgentMcpGrant[]> =>
    (await client.get<AgentMcpGrant[]>(`/agents/${encodeURIComponent(agentId)}/mcp-grants`)).data,
};

// --- Access graph ---------------------------------------------------------------

export interface GraphNode {
  type: 'user' | 'group' | 'agent' | 'mcp';
  id: string;
  label: string;
  /** The record id behind the node (agent id, gateway id, or principal id). */
  ref_id: string;
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: 'access' | 'can_call';
  role: string;
  /** True when the target gateway has Cedar enforcement on. */
  has_policy?: boolean;
}

/** `GET /governance-graph`. */
export interface GovernanceGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** `GET /principals/{id}`. */
export interface PrincipalDetail {
  id: string;
  display_name: string;
  kind: 'user' | 'group';
  user_principal_name?: string | null;
  mail?: string | null;
  job_title?: string | null;
  group_names?: string[];
}

export const governanceGraphApi = {
  get: async (): Promise<GovernanceGraph> => (await client.get<GovernanceGraph>('/governance-graph')).data,
  principal: async (id: string, kind: 'user' | 'group'): Promise<PrincipalDetail> =>
    (await client.get<PrincipalDetail>(`/principals/${encodeURIComponent(id)}`, { params: { kind } })).data,
};

// --- Observability ----------------------------------------------------------------

export type MetricsScope = 'platform' | 'tenant';

/** `GET /agents/{id}/traces`. */
export interface TracePage {
  data: TraceRow[];
  total: number;
  warnings?: string[];
}

export const observabilityApi = {
  getSettings: async (): Promise<ObservabilitySettings> =>
    (await client.get<ObservabilitySettings>('/observability/settings')).data,
  getMetrics: async (
    scope: MetricsScope,
    params: { dateFrom: string; dateTo: string },
  ): Promise<ScopeMetrics> =>
    (await client.get<ScopeMetrics>('/observability/metrics', {
      params: { scope, date_from: params.dateFrom, date_to: params.dateTo },
    })).data,
  getAgentMetrics: async (
    agentId: string,
    params: { dateFrom: string; dateTo: string },
  ): Promise<AgentMetrics> =>
    (await client.get<AgentMetrics>(`/agents/${encodeURIComponent(agentId)}/metrics`, {
      params: { date_from: params.dateFrom, date_to: params.dateTo },
    })).data,
  getAgentTraces: async (
    agentId: string,
    params: { page: number; limit: number },
  ): Promise<TracePage> =>
    (await client.get<TracePage>(`/agents/${encodeURIComponent(agentId)}/traces`, {
      params: { page: params.page, limit: params.limit },
    })).data,
};

// --- Guardrail profiles -----------------------------------------------------------

export const guardrailsApi = {
  list: async (): Promise<GuardrailTemplate[]> => (await client.get<GuardrailTemplate[]>('/guardrails')).data,
  get: async (templateId: string): Promise<GuardrailTemplate> =>
    (await client.get<GuardrailTemplate>(`/guardrails/${encodeURIComponent(templateId)}`)).data,
};

// --- Fleet health (new in the portal) ---------------------------------------------

export type CellHealthState = 'healthy' | 'needs_attention' | 'critical' | 'no_data';

/** Health of one Workstream cell: one agent in one environment. */
export interface FleetCell {
  tenant_id: string;
  /** The agent's id in the cell configuration. A label, not necessarily a registry id. */
  agent_id: string;
  /** `Agent.id` to link to, or null when no registry agent is known for the cell. */
  agent_ref?: string | null;
  environment: string;
  /** A display alias. Never an account id. */
  account_alias: string;
  region: string;
  state: CellHealthState;
  alarms_in_alarm: number;
  /** False when the cell's telemetry could not be read; `state` is then `no_data`. */
  reachable: boolean;
  /** Optional short, safe explanation of the state. */
  detail?: string | null;
}

/** Cell counts per state. The API may add further counters; the UI reads these four. */
export type FleetTotals = Record<CellHealthState, number>;

/** `GET /fleet/health`. */
export interface FleetHealth {
  checked_at: string;
  cells: FleetCell[];
  totals: FleetTotals;
}

export const fleetApi = {
  health: async (): Promise<FleetHealth> => (await client.get<FleetHealth>('/fleet/health')).data,
};

// --- Governance catalog (new in the portal) ----------------------------------------

/** One row of `GET /catalog/models`. */
export interface CatalogModel {
  model_id: string;
  provider: string;
  regions: string[];
  /** For example `approved`, `restricted`, `deprecated`. Rendered verbatim. */
  status: string;
}

/** One row of `GET /catalog/tools`: a tool record from the registry. */
export interface CatalogTool {
  tool_id: string;
  name: string;
  description?: string | null;
  owner?: string | null;
  cost_centre?: string | null;
  status: string;
  version?: string | null;
  target_arn?: string | null;
}

export const catalogApi = {
  models: async (): Promise<CatalogModel[]> => (await client.get<CatalogModel[]>('/catalog/models')).data,
  tools: async (): Promise<CatalogTool[]> => (await client.get<CatalogTool[]>('/catalog/tools')).data,
};
