/**
 * Tests for the GenAI semantic-convention helpers, including parity with the
 * registry and with the shared normalization vectors.
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import * as fs from 'fs';
import * as path from 'path';

import {
  ATTRIBUTE_TYPES,
  GEN_AI_OPERATIONS,
  GEN_AI_PROVIDERS,
  LEGACY_ATTRIBUTE_RENAMES,
  REMOVED_ATTRIBUTES,
  SEMCONV_UPSTREAM_VERSION,
  buildRequestAttributes,
  buildResponseAttributes,
  normalizeAttributes,
  validateRequestAttributes,
} from './index';

const PACKAGE = path.resolve(__dirname, '..');
const registry = JSON.parse(fs.readFileSync(path.join(PACKAGE, 'registry', 'gen-ai.json'), 'utf8'));
const vectors: {
  name: string;
  input: Record<string, unknown>;
  expected: Record<string, unknown>;
  dropped: string[];
}[] = JSON.parse(
  fs.readFileSync(path.join(PACKAGE, 'registry', 'normalization-vectors.json'), 'utf8'),
).vectors;

describe('generated constants match the registry', () => {
  it('covers every attribute and extension with its type', () => {
    const merged: Record<string, { type: string }> = { ...registry.attributes, ...registry.extensions };
    const expected = Object.fromEntries(Object.entries(merged).map(([k, v]) => [k, v.type]));
    expect(ATTRIBUTE_TYPES).toEqual(expected);
  });

  it('carries the pinned upstream version, operations and providers', () => {
    expect(SEMCONV_UPSTREAM_VERSION).toBe(registry.upstream.version);
    expect([...GEN_AI_OPERATIONS]).toEqual(registry.operations);
    expect([...GEN_AI_PROVIDERS]).toEqual(registry.providers);
  });

  it('carries every legacy rename and removal', () => {
    const renames: Record<string, string> = { ...registry.legacyExtensions };
    const removed: string[] = [];
    for (const [legacy, canonical] of Object.entries(registry.legacyAttributes as Record<string, string | null>)) {
      if (canonical === null) removed.push(legacy);
      else renames[legacy] = canonical;
    }
    expect(LEGACY_ATTRIBUTE_RENAMES).toEqual(renames);
    expect([...REMOVED_ATTRIBUTES]).toEqual(removed.sort());
  });

  it('has the Python module generated from the same registry', () => {
    const python = fs.readFileSync(
      path.join(PACKAGE, 'python', 'agenticai_semconv', '_generated.py'),
      'utf8',
    );
    expect(python).toContain(`SEMCONV_UPSTREAM_VERSION = "${registry.upstream.version}"`);
    for (const key of Object.keys({ ...registry.attributes, ...registry.extensions })) {
      expect(python).toContain(`"${key}"`);
    }
  });
});

describe('buildRequestAttributes', () => {
  it('emits canonical gen_ai.* keys', () => {
    const a = buildRequestAttributes({
      operation: 'chat',
      system: 'aws.bedrock',
      modelId: 'anthropic.claude-sonnet-4-5-20250929-v1:0',
      tenantId: 'demo',
      agentId: 'primary',
      conversationId: 'c-1',
      maxTokens: 1024,
      temperature: 0.7,
    });
    expect(a['gen_ai.operation.name']).toBe('chat');
    expect(a['gen_ai.provider.name']).toBe('aws.bedrock');
    expect('gen_ai.system' in a).toBe(false);
    expect(a['gen_ai.request.model']).toContain('claude-sonnet-4-5');
    expect(a['gen_ai.request.max_tokens']).toBe(1024);
    expect(a['gen_ai.request.temperature']).toBe(0.7);
    expect(a['gen_ai.agent.id']).toBe('primary');
    expect(a['gen_ai.conversation.id']).toBe('c-1');
    expect(a['agenticai.tenant.id']).toBe('demo');
    expect(() => validateRequestAttributes(a)).not.toThrow();
  });

  it('omits optional fields when not supplied', () => {
    const a = buildRequestAttributes({ operation: 'chat', system: 'aws.bedrock', modelId: 'm', tenantId: 't', agentId: 'a' });
    expect('gen_ai.request.max_tokens' in a).toBe(false);
    expect('gen_ai.request.temperature' in a).toBe(false);
  });

  it('writes the legacy tool_call operation as execute_tool, with the tool name and call id', () => {
    const a = buildRequestAttributes({
      operation: 'tool_call',
      system: 'aws.bedrock',
      modelId: 'm',
      tenantId: 't',
      agentId: 'a',
      toolName: 'target-demo___tool-echo',
      toolCallId: 'call-1',
    });
    expect(a['gen_ai.operation.name']).toBe('execute_tool');
    expect(a['gen_ai.tool.name']).toBe('target-demo___tool-echo');
    expect(a['gen_ai.tool.call.id']).toBe('call-1');
  });
});

describe('buildResponseAttributes', () => {
  it('emits usage and finish_reasons as a list', () => {
    const a = buildResponseAttributes({ modelId: 'm', inputTokens: 100, outputTokens: 50, finishReason: 'stop', responseId: 'r-1', usageMs: 420 });
    expect(a['gen_ai.response.model']).toBe('m');
    expect(a['gen_ai.response.finish_reasons']).toEqual(['stop']);
    expect(a['gen_ai.usage.input_tokens']).toBe(100);
    expect(a['gen_ai.usage.output_tokens']).toBe(50);
    expect(a['gen_ai.response.id']).toBe('r-1');
    expect(a['agenticai.invocation.latency_ms']).toBe(420);
  });
});

describe('normalizeAttributes', () => {
  it.each(vectors.map((v) => [v.name, v] as const))('%s', (_name, vector) => {
    const result = normalizeAttributes(vector.input);
    expect(result.attributes).toEqual(vector.expected);
    expect(result.dropped).toEqual(vector.dropped);
  });
});

describe('validateRequestAttributes', () => {
  const valid = {
    'gen_ai.operation.name': 'chat',
    'gen_ai.provider.name': 'aws.bedrock',
    'gen_ai.request.model': 'm',
    'agenticai.tenant.id': 't',
  };

  it('accepts canonical and legacy names', () => {
    expect(() => validateRequestAttributes(valid)).not.toThrow();
    expect(() =>
      validateRequestAttributes({ 'gen_ai.operation.name': 'tool_call', 'gen_ai.system': 'aws.bedrock', 'gen_ai.request.model': 'm', 'agenticai.tenant.id': 't' }),
    ).not.toThrow();
  });

  it('rejects a missing required attribute', () => {
    const { 'gen_ai.provider.name': _omitted, ...rest } = valid;
    expect(() => validateRequestAttributes(rest)).toThrow(/missing required gen_ai.provider.name/);
  });

  it('rejects a wrong type and unknown operation or provider', () => {
    expect(() => validateRequestAttributes({ ...valid, 'gen_ai.request.model': 7 })).toThrow(/must be string/);
    expect(() => validateRequestAttributes({ ...valid, 'gen_ai.operation.name': 'summon' })).toThrow(/is not one of/);
    expect(() => validateRequestAttributes({ ...valid, 'gen_ai.provider.name': 'acme' })).toThrow(/is not one of/);
  });
});
