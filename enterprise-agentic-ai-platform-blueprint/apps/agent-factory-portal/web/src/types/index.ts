// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.

/** Wire types shared by more than one screen. Field names match the API exactly. */

export interface ApiValidationErrorItem {
  loc: Array<string | number>;
  msg: string;
  type?: string;
}

/** Error body. `detail` is a message, or a list of per-field validation errors. */
export interface ApiError {
  detail: string | ApiValidationErrorItem[];
  error?: string;
}

/** `GET /observability/settings`. */
export interface ObservabilitySettings {
  /** False when no metrics source is wired in; the dashboard then shows an empty state. */
  configured: boolean;
}

export interface MetricTotals {
  traces: number;
  cost_usd: number;
  tokens: number;
}

/** `GET /agents/{id}/metrics`. */
export interface AgentMetrics {
  /** False when the telemetry source cannot price usage; every `cost_usd` is then 0. Absent means true. */
  cost_available?: boolean;
  /** Short, safe notes about gaps in the data, shown above the charts. */
  warnings?: string[];
  totals: MetricTotals;
  daily: { date: string; traces: number; cost_usd: number; tokens: number }[];
  by_model: { model: string; cost_usd: number; tokens: number }[];
  by_user: { user_id: string; cost_usd: number; traces: number }[];
}

/** `GET /observability/metrics`. */
export interface ScopeMetrics extends AgentMetrics {
  by_agent: {
    agent_id: string;
    agent_name: string;
    tenant_id: string | null;
    totals: MetricTotals;
  }[];
}

/** One row of `GET /agents/{id}/traces`. */
export interface TraceRow {
  id: string;
  timestamp: string | null;
  name: string | null;
  user_id: string | null;
  latency_ms: number | null;
  /** 0 when the cost is not known. */
  cost_usd: number;
  status?: string | null;
  total_tokens?: number | null;
}

export type GuardrailFilterStrength = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
export type GuardrailFilterType = 'HATE' | 'INSULTS' | 'SEXUAL' | 'VIOLENCE' | 'MISCONDUCT' | 'PROMPT_ATTACK';
export type GuardrailPiiAction = 'BLOCK' | 'ANONYMIZE';
export type GuardrailStatus = 'draft' | 'creating' | 'active' | 'updating' | 'failed' | 'deleting' | 'deleted';

export interface ContentFilterConfig {
  type: GuardrailFilterType;
  input_strength: GuardrailFilterStrength;
  output_strength: GuardrailFilterStrength;
}

export interface DeniedTopic {
  name: string;
  definition: string;
  examples: string[];
}

export interface PiiEntityConfig {
  type: string;
  action: GuardrailPiiAction;
}

export interface SensitiveRegexConfig {
  name: string;
  pattern: string;
  description?: string;
  action: GuardrailPiiAction;
}

export interface WordFilterConfig {
  enable_profanity: boolean;
  blocked_words: string[];
}

export interface ContextualGroundingConfig {
  enabled: boolean;
  grounding_threshold: number;
  relevance_threshold: number;
}

/** `GET /guardrails` (array) and `GET /guardrails/{id}`. Shown as a guardrail profile. */
export interface GuardrailTemplate {
  template_id: string;
  name: string;
  description?: string;
  status: GuardrailStatus;
  guardrail_id?: string;
  guardrail_arn?: string;
  guardrail_version?: string;
  content_filters: ContentFilterConfig[];
  denied_topics: DeniedTopic[];
  pii_entities: PiiEntityConfig[];
  sensitive_regexes: SensitiveRegexConfig[];
  word_filter?: WordFilterConfig;
  contextual_grounding?: ContextualGroundingConfig;
  status_history: { status: string; timestamp: string; message?: string }[];
  created_by?: string;
  created_at: string;
  updated_at: string;
}
