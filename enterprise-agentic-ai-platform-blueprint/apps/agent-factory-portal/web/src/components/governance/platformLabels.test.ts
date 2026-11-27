// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, expect, it } from 'vitest';
import {
  identityStatusLabel,
  mcpHostLabel,
  platformHostLabel,
  platformLabel,
  platformLabelOr,
  runtimeHandleField,
} from './platformLabels';

describe('platform labels', () => {
  it('names the platform Workstream cells run on', () => {
    expect(platformLabel('aws_bedrock')).toBe('Amazon Bedrock AgentCore');
    expect(platformHostLabel('aws_bedrock')).toBe('AWS');
  });

  it('shows an unrecognised key as recorded, and a missing one as a dash or the fallback', () => {
    expect(platformLabel('custom_host')).toBe('custom_host');
    expect(platformLabel(null)).toBe('—');
    expect(platformLabelOr(undefined, 'Platform not recorded')).toBe('Platform not recorded');
    expect(platformHostLabel('')).toBe('');
  });

  it('is not fooled by a prototype key', () => {
    expect(platformLabel('constructor')).toBe('constructor');
    expect(platformHostLabel('toString')).toBe('toString');
  });
});

describe('mcpHostLabel', () => {
  it('tags gateway and runtime kinds as AWS and standard as external', () => {
    expect(mcpHostLabel('gateway')).toBe('AWS');
    expect(mcpHostLabel('runtime')).toBe('AWS');
    expect(mcpHostLabel('standard')).toBe('External');
    expect(mcpHostLabel('other')).toBe('');
  });
});

describe('runtimeHandleField', () => {
  it('prefers the runtime ARN, then a generic handle', () => {
    expect(runtimeHandleField({ agent_arn: 'arn:example', runtime_handle: 'h' })).toEqual({
      label: 'Runtime ARN',
      value: 'arn:example',
      copyLabel: 'runtime ARN',
    });
    expect(runtimeHandleField({ runtime_handle: 'h' })?.label).toBe('Runtime handle');
    expect(runtimeHandleField({})).toBeNull();
  });
});

describe('identityStatusLabel', () => {
  it('labels each status and treats anything else as unknown', () => {
    expect(identityStatusLabel('provisioned')).toBe('Provisioned');
    expect(identityStatusLabel('none')).toBe('No workload identity');
    expect(identityStatusLabel('failed')).toBe('Provisioning failed');
    expect(identityStatusLabel('pending')).toBe('Provisioning');
    expect(identityStatusLabel('weird')).toBe('Unknown');
    expect(identityStatusLabel(undefined)).toBe('Unknown');
  });
});
