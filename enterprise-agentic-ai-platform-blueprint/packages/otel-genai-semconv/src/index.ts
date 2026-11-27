/**
 * @agenticai/otel-genai-semconv
 *
 * Span attribute helpers for GenAI operations, aligned to the OpenTelemetry
 * GenAI semantic conventions (`gen_ai.*`). The attribute names, operation
 * names and provider names come from one registry
 * (`registry/gen-ai.json`), a curated subset pinned to one upstream version,
 * from which `scripts/generate.py` writes the TypeScript module used here and
 * the Python module agents import (`python/agenticai_semconv`). Both
 * implementations are held to the same normalization vectors
 * (`registry/normalization-vectors.json`).
 *
 * Why normalization matters: the evaluation gates, the fleet views and any
 * external APM read spans by attribute name. Frameworks still emit names the
 * conventions have since renamed (`gen_ai.system`, `gen_ai.usage.prompt_tokens`),
 * so readers call `normalizeAttributes` once and query canonical names only.
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import {
  AGENTICAI_INVOCATION_LATENCY_MS,
  AGENTICAI_TENANT_ID,
  GEN_AI_AGENT_ID,
  GEN_AI_CONVERSATION_ID,
  GEN_AI_OPERATIONS,
  GEN_AI_OPERATION_NAME,
  GEN_AI_PROVIDERS,
  GEN_AI_PROVIDER_NAME,
  GEN_AI_REQUEST_MAX_TOKENS,
  GEN_AI_REQUEST_MODEL,
  GEN_AI_REQUEST_TEMPERATURE,
  GEN_AI_REQUEST_TOP_P,
  GEN_AI_RESPONSE_FINISH_REASONS,
  GEN_AI_RESPONSE_ID,
  GEN_AI_RESPONSE_MODEL,
  GEN_AI_TOOL_CALL_ID,
  GEN_AI_TOOL_NAME,
  GEN_AI_USAGE_INPUT_TOKENS,
  GEN_AI_USAGE_OUTPUT_TOKENS,
  GenAiOperationName,
  GenAiProviderName,
  LEGACY_ATTRIBUTE_RENAMES,
  LEGACY_VALUE_RENAMES,
  LIST_ATTRIBUTES,
  REMOVED_ATTRIBUTES,
  REQUIRED_ATTRIBUTES,
} from './generated/registry';

export * from './generated/registry';

/** Operation names accepted by the builders. `tool_call` is the legacy spelling of `execute_tool`. */
export type GenAiOperation = GenAiOperationName | 'tool_call';

/** Provider names accepted by the builders. */
export type GenAiSystem = GenAiProviderName;

export type AttributeValue = string | number | boolean | readonly string[];

export interface GenAiRequestSpanInput {
  readonly operation: GenAiOperation;
  /** Provider name (`gen_ai.provider.name`). */
  readonly system: GenAiSystem;
  readonly modelId: string;
  readonly tenantId: string;
  readonly agentId: string;
  readonly conversationId?: string;
  readonly maxTokens?: number;
  readonly temperature?: number;
  readonly topP?: number;
  /** Tool name, for `execute_tool`. */
  readonly toolName?: string;
  /** Tool call id, for `execute_tool`. */
  readonly toolCallId?: string;
}

export type GenAiFinishReason = 'stop' | 'length' | 'content_filter' | 'tool_calls' | 'error';

export interface GenAiResponseSpanInput {
  readonly modelId: string;
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly finishReason: GenAiFinishReason | readonly GenAiFinishReason[];
  readonly responseId?: string;
  readonly usageMs?: number;
}

/** Request-side span attributes, canonical names only. */
export function buildRequestAttributes(input: GenAiRequestSpanInput): Record<string, AttributeValue> {
  const out: Record<string, AttributeValue> = {
    [GEN_AI_OPERATION_NAME]: input.operation === 'tool_call' ? 'execute_tool' : input.operation,
    [GEN_AI_PROVIDER_NAME]: input.system,
    [GEN_AI_REQUEST_MODEL]: input.modelId,
    [GEN_AI_AGENT_ID]: input.agentId,
    [AGENTICAI_TENANT_ID]: input.tenantId,
  };
  if (input.conversationId !== undefined) out[GEN_AI_CONVERSATION_ID] = input.conversationId;
  if (input.maxTokens !== undefined) out[GEN_AI_REQUEST_MAX_TOKENS] = input.maxTokens;
  if (input.temperature !== undefined) out[GEN_AI_REQUEST_TEMPERATURE] = input.temperature;
  if (input.topP !== undefined) out[GEN_AI_REQUEST_TOP_P] = input.topP;
  if (input.toolName !== undefined) out[GEN_AI_TOOL_NAME] = input.toolName;
  if (input.toolCallId !== undefined) out[GEN_AI_TOOL_CALL_ID] = input.toolCallId;
  return out;
}

/** Response-side span attributes, canonical names only. */
export function buildResponseAttributes(input: GenAiResponseSpanInput): Record<string, AttributeValue> {
  const reasons = typeof input.finishReason === 'string' ? [input.finishReason] : [...input.finishReason];
  const out: Record<string, AttributeValue> = {
    [GEN_AI_RESPONSE_MODEL]: input.modelId,
    [GEN_AI_RESPONSE_FINISH_REASONS]: reasons,
    [GEN_AI_USAGE_INPUT_TOKENS]: input.inputTokens,
    [GEN_AI_USAGE_OUTPUT_TOKENS]: input.outputTokens,
  };
  if (input.responseId) out[GEN_AI_RESPONSE_ID] = input.responseId;
  if (input.usageMs !== undefined) out[AGENTICAI_INVOCATION_LATENCY_MS] = input.usageMs;
  return out;
}

export interface NormalizedAttributes {
  /** Attributes under canonical names. */
  readonly attributes: Record<string, unknown>;
  /** Removed attributes that were present and have been dropped, sorted. */
  readonly dropped: string[];
}

/**
 * Rename legacy attribute names and values to canonical ones, wrap a single
 * value of a list-typed attribute in a list, and drop attributes the
 * conventions removed. When a legacy and a canonical name are both present,
 * the canonical one wins. Unknown attributes are kept unchanged.
 */
export function normalizeAttributes(input: Readonly<Record<string, unknown>>): NormalizedAttributes {
  const attributes: Record<string, unknown> = {};
  const dropped: string[] = [];
  const canonicalValue = (key: string, value: unknown): unknown => {
    let next = value;
    const renames = LEGACY_VALUE_RENAMES[key];
    if (renames && typeof next === 'string' && next in renames) next = renames[next];
    if (LIST_ATTRIBUTES.includes(key) && !Array.isArray(next)) next = [next];
    return next;
  };
  for (const [key, value] of Object.entries(input)) {
    if (REMOVED_ATTRIBUTES.includes(key)) {
      dropped.push(key);
      continue;
    }
    if (key in LEGACY_ATTRIBUTE_RENAMES) continue;
    attributes[key] = canonicalValue(key, value);
  }
  for (const [legacy, canonical] of Object.entries(LEGACY_ATTRIBUTE_RENAMES)) {
    if (legacy in input && !(canonical in attributes)) {
      attributes[canonical] = canonicalValue(canonical, input[legacy]);
    }
  }
  return { attributes, dropped: dropped.sort() };
}

/**
 * Validate request attributes after normalization. Throws with an actionable
 * message on a missing required attribute, a wrong type, or an operation or
 * provider name outside the pinned conventions.
 */
export function validateRequestAttributes(attrs: Readonly<Record<string, unknown>>): void {
  const { attributes } = normalizeAttributes(attrs);
  for (const key of REQUIRED_ATTRIBUTES) {
    if (!(key in attributes)) throw new Error(`OTel GenAI sem-conv: missing required ${key}`);
    if (typeof attributes[key] !== 'string') throw new Error(`OTel GenAI sem-conv: ${key} must be string`);
  }
  const operation = attributes[GEN_AI_OPERATION_NAME] as string;
  if (!(GEN_AI_OPERATIONS as readonly string[]).includes(operation)) {
    throw new Error(
      `OTel GenAI sem-conv: ${GEN_AI_OPERATION_NAME} '${operation}' is not one of ${GEN_AI_OPERATIONS.join(', ')}`,
    );
  }
  const provider = attributes[GEN_AI_PROVIDER_NAME] as string;
  if (!(GEN_AI_PROVIDERS as readonly string[]).includes(provider)) {
    throw new Error(
      `OTel GenAI sem-conv: ${GEN_AI_PROVIDER_NAME} '${provider}' is not one of ${GEN_AI_PROVIDERS.join(', ')}`,
    );
  }
}
