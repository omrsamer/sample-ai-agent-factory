// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, it, expect } from 'vitest';
import { computeDrift } from './mcpDrift';

describe('computeDrift', () => {
  it('declared and granted → connected', () => {
    expect(computeDrift(['m1'], ['m1'])).toEqual([{ id: 'm1', state: 'connected' }]);
  });

  it('declared only → not_granted', () => {
    expect(computeDrift(['m1'], [])).toEqual([{ id: 'm1', state: 'not_granted' }]);
  });

  it('granted only → unused_grant', () => {
    expect(computeDrift(['m1'], ['m1', 'm2'])).toEqual([
      { id: 'm1', state: 'connected' },
      { id: 'm2', state: 'unused_grant' },
    ]);
  });

  it('undefined declared → every granted row is connected', () => {
    expect(computeDrift(undefined, ['m1', 'm2'])).toEqual([
      { id: 'm1', state: 'connected' },
      { id: 'm2', state: 'connected' },
    ]);
  });

  it('empty declared → no unused flags', () => {
    expect(computeDrift([], ['m1'])).toEqual([{ id: 'm1', state: 'connected' }]);
  });

  it('mixes all three states, granted first, then declared-only, without duplicates', () => {
    expect(computeDrift(['m3', 'm1', 'm3'], ['m1', 'm2', 'm1'])).toEqual([
      { id: 'm1', state: 'connected' },
      { id: 'm2', state: 'unused_grant' },
      { id: 'm3', state: 'not_granted' },
    ]);
  });
});
