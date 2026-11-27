// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/// <reference types="node" />
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  DATA_CLASSIFICATIONS,
  EMPTY_DRAFT,
  ENVIRONMENTS,
  GOVERNED_REFERENCE_FIELDS,
  IDENTITY_FIELDS,
  LENGTHS,
  PATTERNS,
  REQUIRED_FIELDS,
  RISK_CLASSES,
  SCHEMA_VERSION,
  compareVersions,
  documentDiff,
  draftFromDocument,
  fieldForDocumentPath,
  fieldForMessage,
  inputFromDraft,
  validateDraft,
  type RegistrationDraft,
} from './governanceSchema';

/** The schema this module copies. Read here, in a test, so production code never crosses the package boundary. */
const schema = JSON.parse(
  readFileSync(new URL('../../../../../packages/agent-registry/schemas/agent-governance-1.0.json', import.meta.url), 'utf8'),
) as {
  $id: string;
  required: string[];
  properties: Record<string, { enum?: string[]; pattern?: string; minLength?: number; maxLength?: number; const?: string; items?: { pattern?: string }; properties?: Record<string, { minLength?: number; maxLength?: number }>; required?: string[] }>;
};
const prop = schema.properties;

// A placeholder account id: one repeated digit.
const ACCOUNT = '1'.repeat(12);
const RUNTIME_ARN = `arn:aws:bedrock-agentcore:eu-west-1:${ACCOUNT}:runtime/orders_assistant-abc123`;
const GATEWAY_ARN = `arn:aws:bedrock-agentcore:eu-west-1:${ACCOUNT}:gateway/orders-gateway`;

const VALID: RegistrationDraft = {
  ...EMPTY_DRAFT,
  tenantId: 'retail',
  agentId: 'orders-assistant',
  environment: 'prod',
  ownerGroup: 'retail-platform',
  businessPurpose: 'Answers order status questions.',
  riskClass: 'limited',
  dataClassification: 'internal',
  costCentre: 'CC-100',
};

describe('the copied constraints match the schema file', () => {
  it('has the same schema id and version constant', () => {
    expect(SCHEMA_VERSION).toBe(schema.$id);
    expect(SCHEMA_VERSION).toBe(prop.schemaVersion.const);
  });

  it('has the same enums', () => {
    expect([...ENVIRONMENTS]).toEqual(prop.environment.enum);
    expect([...RISK_CLASSES]).toEqual(prop.riskClass.enum);
    expect([...DATA_CLASSIFICATIONS]).toEqual(prop.dataClassification.enum);
  });

  it('has the same patterns', () => {
    expect(PATTERNS.tenantId).toBe(prop.tenantId.pattern);
    expect(PATTERNS.agentId).toBe(prop.agentId.pattern);
    expect(PATTERNS.toolId).toBe(prop.subscribedToolIds.items?.pattern);
    expect(PATTERNS.runtimeArn).toBe(prop.runtimeArn.pattern);
    expect(PATTERNS.gatewayArn).toBe(prop.gatewayArn.pattern);
    expect(PATTERNS.recordVersion).toBe(prop.recordVersion.pattern);
  });

  it('has the same length limits', () => {
    for (const field of ['applicationId', 'ownerGroup', 'contact', 'businessPurpose', 'costCentre', 'framework'] as const) {
      expect({ field, ...LENGTHS[field] }).toEqual({ field, min: prop[field].minLength ?? 0, max: prop[field].maxLength });
    }
    const goldenPath = prop.goldenPath.properties!;
    expect(LENGTHS.goldenPathName).toEqual({ min: goldenPath.name.minLength, max: goldenPath.name.maxLength });
    expect(LENGTHS.goldenPathVersion).toEqual({ min: goldenPath.version.minLength, max: goldenPath.version.maxLength });
    expect(prop.goldenPath.required).toEqual(['name', 'version']);
  });

  it('has the same required fields', () => {
    expect([...REQUIRED_FIELDS]).toEqual(schema.required);
  });

  it('sends only properties the schema defines, under their snake_case request names', () => {
    const camel = (key: string) => key.replace(/_([a-z])/g, (_m, c: string) => c.toUpperCase());
    const input = inputFromDraft({
      ...VALID,
      applicationId: 'app-1',
      contact: 'retail-platform@example.com',
      framework: 'strands',
      goldenPathName: 'python-agent',
      goldenPathVersion: '2.1.0',
      runtimeArn: RUNTIME_ARN,
      gatewayArn: GATEWAY_ARN,
      subscribedToolIds: ['get-order'],
    });
    expect(Object.keys(input).every((key) => key === key.toLowerCase())).toBe(true);
    for (const key of Object.keys(input)) expect(Object.keys(prop)).toContain(camel(key));
    // Every required property is sent, except the schema version, which the server sets.
    const sent = Object.keys(input).map(camel);
    for (const key of schema.required.filter((k) => k !== 'schemaVersion')) expect(sent).toContain(key);
    expect(input).not.toHaveProperty('schema_version');
    expect(Object.keys(input.golden_path ?? {})).toEqual(prop.goldenPath.required);
  });
});

describe('validateDraft', () => {
  it('accepts a complete draft, with or without the optional fields', () => {
    expect(validateDraft(VALID)).toEqual({});
    expect(
      validateDraft({ ...VALID, runtimeArn: RUNTIME_ARN, gatewayArn: GATEWAY_ARN, subscribedToolIds: ['get-order'], goldenPathName: 'p', goldenPathVersion: '1' }),
    ).toEqual({});
  });

  it('names every missing required field', () => {
    expect(Object.keys(validateDraft({ ...EMPTY_DRAFT, recordVersion: '' })).sort()).toEqual(
      ['agentId', 'businessPurpose', 'costCentre', 'dataClassification', 'ownerGroup', 'riskClass', 'tenantId'].sort(),
    );
  });

  it('applies the identifier pattern', () => {
    for (const bad of ['Orders', 'orders_assistant', '-orders', 'a'.repeat(64), 'orders assistant']) {
      expect(validateDraft({ ...VALID, agentId: bad }).agentId).toBeDefined();
      expect(validateDraft({ ...VALID, tenantId: bad }).tenantId).toBeDefined();
    }
    expect(validateDraft({ ...VALID, agentId: 'a'.repeat(63) }).agentId).toBeUndefined();
  });

  it('rejects values outside the enums', () => {
    expect(validateDraft({ ...VALID, riskClass: 'severe' }).riskClass).toBeDefined();
    expect(validateDraft({ ...VALID, dataClassification: 'Internal' }).dataClassification).toBeDefined();
    expect(validateDraft({ ...VALID, environment: 'staging' }).environment).toBeDefined();
  });

  it('applies the ARN patterns to the right resource type', () => {
    expect(validateDraft({ ...VALID, runtimeArn: GATEWAY_ARN }).runtimeArn).toBeDefined();
    expect(validateDraft({ ...VALID, gatewayArn: RUNTIME_ARN }).gatewayArn).toBeDefined();
    expect(validateDraft({ ...VALID, runtimeArn: 'arn:aws:lambda:eu-west-1:1:function:x' }).runtimeArn).toBeDefined();
    expect(validateDraft({ ...VALID, runtimeArn: `${RUNTIME_ARN} ` }).runtimeArn).toBeUndefined();
  });

  it('enforces the length limits', () => {
    expect(validateDraft({ ...VALID, businessPurpose: 'x'.repeat(2001) }).businessPurpose).toBeDefined();
    expect(validateDraft({ ...VALID, businessPurpose: 'x'.repeat(2000) }).businessPurpose).toBeUndefined();
    expect(validateDraft({ ...VALID, framework: 'x'.repeat(65) }).framework).toBeDefined();
    expect(validateDraft({ ...VALID, ownerGroup: '   ' }).ownerGroup).toBeDefined();
  });

  it('requires both halves of the golden path, or neither', () => {
    expect(validateDraft({ ...VALID, goldenPathName: 'python-agent' }).goldenPathVersion).toBeDefined();
    expect(validateDraft({ ...VALID, goldenPathVersion: '2.1.0' }).goldenPathName).toBeDefined();
  });

  it('checks the record version and the tool ids', () => {
    expect(validateDraft({ ...VALID, recordVersion: '1.0' }).recordVersion).toBeDefined();
    expect(validateDraft({ ...VALID, recordVersion: 'v1.0.0' }).recordVersion).toBeDefined();
    expect(validateDraft({ ...VALID, recordVersion: '' }).recordVersion).toBeUndefined();
    expect(validateDraft({ ...VALID, subscribedToolIds: ['get-order', 'Bad_Id'] }).subscribedToolIds).toBeDefined();
  });

  it('accepts an unchanged version on an edit and requires a changed one to be higher', () => {
    expect(validateDraft({ ...VALID, recordVersion: '1.2.3' }, '1.2.3').recordVersion).toBeUndefined();
    expect(validateDraft({ ...VALID, recordVersion: '1.3.0' }, '1.2.3').recordVersion).toBeUndefined();
    expect(validateDraft({ ...VALID, recordVersion: '1.2.2' }, '1.2.3').recordVersion).toMatch(/higher than 1\.2\.3/);
    expect(validateDraft({ ...VALID, recordVersion: '1.10.0' }, '1.9.9').recordVersion).toBeUndefined();
  });
});

describe('inputFromDraft and draftFromDocument', () => {
  it('omits empty optional fields instead of sending empty strings', () => {
    expect(Object.keys(inputFromDraft(VALID)).sort()).toEqual(
      ['agent_id', 'business_purpose', 'cost_centre', 'data_classification', 'environment', 'owner_group', 'record_version', 'risk_class', 'tenant_id'].sort(),
    );
  });

  it('trims text, and sorts and removes duplicates from tool ids', () => {
    const input = inputFromDraft({ ...VALID, ownerGroup: '  retail-platform ', subscribedToolIds: ['b', 'a', 'b'] });
    expect(input.owner_group).toBe('retail-platform');
    expect(input.subscribed_tool_ids).toEqual(['a', 'b']);
  });

  it('carries through properties the form does not edit, and drops null ones', () => {
    const base = { ...inputFromDraft(VALID), evaluation: { verdict: 'passed' }, memory_id: 'mem-1', source_revision: null };
    const input = inputFromDraft({ ...VALID, costCentre: 'CC-200' }, base);
    expect(input.evaluation).toEqual({ verdict: 'passed' });
    expect(input.memory_id).toBe('mem-1');
    expect(input).not.toHaveProperty('source_revision');
    expect(input.cost_centre).toBe('CC-200');
  });

  it('drops an optional field that was cleared, even if the base had it', () => {
    const base = inputFromDraft({ ...VALID, contact: 'retail-platform@example.com' });
    expect(inputFromDraft(VALID, base)).not.toHaveProperty('contact');
  });

  it('never sends the schema version, which the server sets', () => {
    expect(inputFromDraft(VALID, { schema_version: 'agenticai.agent-governance/1.0' })).not.toHaveProperty('schema_version');
  });

  it('sends the version on an edit only when the user raised it', () => {
    expect(inputFromDraft({ ...VALID, recordVersion: '1.2.3' }, null, '1.2.3')).not.toHaveProperty('record_version');
    expect(inputFromDraft({ ...VALID, recordVersion: '1.3.0' }, null, '1.2.3').record_version).toBe('1.3.0');
    expect(inputFromDraft({ ...VALID, recordVersion: '' })).not.toHaveProperty('record_version');
    expect(inputFromDraft(VALID).record_version).toBe('1.0.0');
  });

  it('round-trips', () => {
    const full: RegistrationDraft = { ...VALID, goldenPathName: 'python-agent', goldenPathVersion: '2.1.0', runtimeArn: RUNTIME_ARN, subscribedToolIds: ['get-order'] };
    expect(draftFromDocument(inputFromDraft(full))).toEqual(full);
  });

  it('never throws on a malformed document', () => {
    for (const doc of [null, undefined, {}, { subscribed_tool_ids: 'x', golden_path: null, tenant_id: 7 }]) {
      expect(() => draftFromDocument(doc as never)).not.toThrow();
    }
  });
});

describe('compareVersions', () => {
  it('compares numerically, not as text', () => {
    expect(compareVersions('1.10.0', '1.9.9')).toBeGreaterThan(0);
    expect(compareVersions('2.0.0', '10.0.0')).toBeLessThan(0);
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
  });
});

describe('fieldForDocumentPath', () => {
  it('maps a server error location to the form field, by request name or stored name', () => {
    expect(fieldForDocumentPath(['body', 'agent_id'])).toBe('agentId');
    expect(fieldForDocumentPath(['body', 'risk_class'])).toBe('riskClass');
    expect(fieldForDocumentPath(['body', 'golden_path', 'version'])).toBe('goldenPathVersion');
    expect(fieldForDocumentPath(['body', 'subscribed_tool_ids', 2])).toBe('subscribedToolIds');
    expect(fieldForDocumentPath(['body', 'document', 'agentId'])).toBe('agentId');
    expect(fieldForDocumentPath(['body', 'document', 'goldenPath', 'name'])).toBe('goldenPathName');
  });

  it('finds the field a plain message is about', () => {
    expect(fieldForMessage('document.riskClass must be one of minimal, limited, high, unacceptable')).toBe('riskClass');
    expect(fieldForMessage('document.goldenPath.version is too long')).toBe('goldenPathVersion');
    expect(fieldForMessage('tenant_id must equal the record’s tenant')).toBe('tenantId');
    expect(fieldForMessage('A record of that name already exists')).toBeNull();
    expect(fieldForMessage('')).toBeNull();
  });

  it('answers null for a location it cannot place', () => {
    expect(fieldForDocumentPath(['body'])).toBeNull();
    expect(fieldForDocumentPath(['body', 'evaluation', 'verdict'])).toBeNull();
    expect(fieldForDocumentPath(['body', 'document', 'constructor'])).toBeNull();
  });
});

describe('documentDiff', () => {
  it('lists only the fields that changed', () => {
    const before = inputFromDraft({ ...VALID, subscribedToolIds: ['a', 'b'] });
    const after = inputFromDraft({ ...VALID, costCentre: 'CC-200', subscribedToolIds: ['b', 'a', 'c'] });
    expect(documentDiff(before, after)).toEqual([
      { field: 'costCentre', label: 'Cost centre', before: 'CC-100', after: 'CC-200' },
      { field: 'subscribedToolIds', label: 'Subscribed tools', before: 'a, b', after: 'a, b, c' },
    ]);
  });

  it('leaves the record version out, since the server raises it on every update', () => {
    const before = inputFromDraft({ ...VALID, recordVersion: '1.0.0' });
    const after = inputFromDraft({ ...VALID, recordVersion: '1.0.1' });
    expect(documentDiff(before, after)).toEqual([]);
  });

  it('shows an optional field that was not sent again as removed', () => {
    const before = inputFromDraft({ ...VALID, contact: 'retail-platform@example.com' });
    expect(documentDiff(before, inputFromDraft(VALID))).toEqual([
      { field: 'contact', label: 'Contact', before: 'retail-platform@example.com', after: '' },
    ]);
  });

  it('is empty when nothing changed or there is nothing to compare with', () => {
    const doc = inputFromDraft(VALID);
    expect(documentDiff(doc, doc)).toEqual([]);
    expect(documentDiff(null, doc)).toEqual([]);
  });
});

describe('locked fields', () => {
  it('governed references are the runtime, gateway, subscriptions, risk class and data classification', () => {
    expect([...GOVERNED_REFERENCE_FIELDS].sort()).toEqual(
      ['dataClassification', 'gatewayArn', 'riskClass', 'runtimeArn', 'subscribedToolIds'].sort(),
    );
  });

  it('the identity of a record is its tenant, agent id and environment', () => {
    expect([...IDENTITY_FIELDS]).toEqual(['tenantId', 'agentId', 'environment']);
  });
});
