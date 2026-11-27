// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, expect, it } from 'vitest';
import type { UserTenant } from '../../api/client';
import { resolveTenantName, tenantNames } from './tenantUi';

const tenant = (id: string, name: string): UserTenant => ({ id, name, line_of_business: 'Example', stages: {} });
const MINE = [tenant('t-orders', 'Orders'), tenant('t-returns', 'Returns')];

describe('resolveTenantName', () => {
  it('finds the name in the first directory that knows the id', () => {
    expect(resolveTenantName('t-returns', MINE)).toBe('Returns');
    expect(resolveTenantName('t-other', MINE, [tenant('t-other', 'Other')])).toBe('Other');
  });

  it('answers null for an unknown or missing id, and tolerates missing directories', () => {
    expect(resolveTenantName('t-unknown', MINE)).toBeNull();
    expect(resolveTenantName(null, MINE)).toBeNull();
    expect(resolveTenantName('t-orders', undefined, null)).toBeNull();
  });
});

describe('tenantNames', () => {
  it('joins the names in the given order', () => {
    expect(tenantNames(MINE)).toBe('Orders, Returns');
    expect(tenantNames([])).toBe('');
  });
});
