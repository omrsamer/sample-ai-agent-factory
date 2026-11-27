// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import type { FleetCell } from '../api/client';
import { cellStateView, fleetTotals, sortCells } from './fleetHealth';

const cell = (over: Partial<FleetCell>): FleetCell => ({
  tenant_id: 't1',
  agent_id: 'a1',
  environment: 'prod',
  account_alias: 'workstream-a-prod',
  region: 'eu-west-1',
  state: 'healthy',
  alarms_in_alarm: 0,
  reachable: true,
  ...over,
});

describe('cellStateView', () => {
  it('labels each known state', () => {
    expect(cellStateView('healthy').label).toBe('Healthy');
    expect(cellStateView('needs_attention').label).toBe('Needs attention');
    expect(cellStateView('critical').label).toBe('Critical');
    expect(cellStateView('no_data').label).toBe('No data');
  });

  it('reads an unknown state as no data, never as healthy', () => {
    for (const s of ['', 'ok', 'HEALTHY', 'constructor']) {
      expect(cellStateView(s).label).toBe('No data');
    }
  });
});

describe('sortCells', () => {
  it('puts the worst cells first, then orders by tenant, agent and environment', () => {
    const cells = [
      cell({ agent_id: 'b', state: 'healthy' }),
      cell({ agent_id: 'a', state: 'no_data' }),
      cell({ agent_id: 'c', state: 'critical' }),
      cell({ agent_id: 'a', state: 'needs_attention', environment: 'prod' }),
      cell({ agent_id: 'a', state: 'needs_attention', environment: 'nonprod' }),
    ];
    expect(sortCells(cells).map((c) => `${c.state}/${c.agent_id}/${c.environment}`)).toEqual([
      'critical/c/prod',
      'needs_attention/a/nonprod',
      'needs_attention/a/prod',
      'no_data/a/prod',
      'healthy/b/prod',
    ]);
  });

  it('does not mutate its input', () => {
    const cells = [cell({ state: 'healthy' }), cell({ state: 'critical' })];
    sortCells(cells);
    expect(cells.map((c) => c.state)).toEqual(['healthy', 'critical']);
  });
});

describe('fleetTotals', () => {
  it('uses complete totals from the API', () => {
    const totals = { healthy: 4, needs_attention: 1, critical: 0, no_data: 2 };
    expect(fleetTotals({ cells: [], totals })).toEqual(totals);
  });

  it('counts the cells when totals are missing or partial', () => {
    const cells = [cell({ state: 'healthy' }), cell({ state: 'critical' }), cell({ state: 'weird' as FleetCell['state'] })];
    const expected = { healthy: 1, needs_attention: 0, critical: 1, no_data: 1 };
    expect(fleetTotals({ cells, totals: undefined as never })).toEqual(expected);
    expect(fleetTotals({ cells, totals: { healthy: 9 } as never })).toEqual(expected);
  });

  it('answers zeros before the first load', () => {
    expect(fleetTotals(null)).toEqual({ healthy: 0, needs_attention: 0, critical: 0, no_data: 0 });
  });
});
