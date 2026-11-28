// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import { LIFECYCLE_OPTIONS, lifecycleBadge, nameSegments, tenantBadge } from './agentUi';

describe('nameSegments', () => {
  it('lets a name break after a hyphen or an underscore, never inside a word', () => {
    expect(nameSegments('agenticai-travel-agent')).toEqual(['agenticai-', 'travel-', 'agent']);
    expect(nameSegments('employee_commute_advisor')).toEqual(['employee_', 'commute_', 'advisor']);
    expect(nameSegments('orders_assistant-v2')).toEqual(['orders_', 'assistant-', 'v2']);
  });

  it('keeps every character, in order', () => {
    for (const name of ['agenticai-travel-agent', 'a--b', '-leading', 'trailing_', 'plain', 'x_y-z__w']) {
      expect(nameSegments(name).join('')).toBe(name);
    }
  });

  it('returns a name without separators whole, and nothing for an empty name', () => {
    expect(nameSegments('orders')).toEqual(['orders']);
    expect(nameSegments('')).toEqual([]);
  });
});

describe('badges', () => {
  it('says "None" for an agent with no tenant, in words', () => {
    expect(tenantBadge(null).label).toBe('None');
    expect(tenantBadge('  ').label).toBe('None');
    expect(tenantBadge('ws2').label).toBe('ws2');
  });

  it('labels the lifecycle states and shows an unknown one as recorded', () => {
    expect(lifecycleBadge('pending_approval').label).toBe('Pending approval');
    expect(lifecycleBadge('approved').label).toBe('Approved');
    // The registry says DEPRECATED; the portal says retired.
    expect(lifecycleBadge('deprecated').label).toBe('Retired');
    expect(LIFECYCLE_OPTIONS.find((o) => o.value === 'deprecated')?.label).toBe('Retired');
    expect(lifecycleBadge('archived').label).toBe('archived');
  });
});
