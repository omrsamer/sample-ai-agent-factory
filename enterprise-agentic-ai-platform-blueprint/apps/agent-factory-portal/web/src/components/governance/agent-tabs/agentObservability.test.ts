// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, expect, it } from 'vitest';
import type { TraceRow } from '../../../types';
import { COST_UNAVAILABLE, NOT_RECORDED, costText, emptyState, fmtUsd, mapTraceRows, totalPages } from './agentObservability';

const FULL: TraceRow = {
  id: 'trace-0001',
  timestamp: '2026-03-01T10:15:00Z',
  name: 'invoke',
  user_id: 'caller-1',
  latency_ms: 1234.4,
  cost_usd: 0.0123,
};

describe('mapTraceRows', () => {
  it('maps a populated trace into display cells, keeping the id and the raw row', () => {
    const [row] = mapTraceRows([FULL]);
    expect(row.id).toBe('trace-0001');
    expect(row.name).toBe('invoke');
    expect(row.user).toBe('caller-1');
    expect(row.latency).toMatch(/^1[,.\s]?234 ms$/);
    expect(row.cost).toBe(fmtUsd(0.0123));
    expect(row.timestamp).not.toBe(NOT_RECORDED);
    expect(row.raw).toBe(FULL);
  });

  it('renders every missing field as a dash', () => {
    const [row] = mapTraceRows([{ id: 't', timestamp: null, name: null, user_id: null, latency_ms: null, cost_usd: 0 }]);
    expect(row.timestamp).toBe(NOT_RECORDED);
    expect(row.name).toBe(NOT_RECORDED);
    expect(row.user).toBe(NOT_RECORDED);
    expect(row.latency).toBe(NOT_RECORDED);
  });

  it('shows an unparseable timestamp as recorded', () => {
    expect(mapTraceRows([{ ...FULL, timestamp: 'yesterday' }])[0].timestamp).toBe('yesterday');
  });

  it('shows an unpriced trace in words, not as $0.00, and carries tokens and status', () => {
    const [row] = mapTraceRows([{ ...FULL, name: null, cost_usd: 0, total_tokens: 1500, status: 'ok' }]);
    expect(row.cost).toBe('Not priced');
    expect(row.tokens).toMatch(/^1[,.\s]?500$/);
    expect(row.status).toBe('ok');
    expect(mapTraceRows([FULL])[0].tokens).toBe(NOT_RECORDED);
  });

  it('maps an empty list to an empty list', () => {
    expect(mapTraceRows([])).toEqual([]);
  });
});

describe('fmtUsd', () => {
  it('does not round a sub-cent cost away to zero', () => {
    expect(fmtUsd(0.000123)).toMatch(/0[.,]000123$/);
    expect(fmtUsd(0.0123)).toMatch(/0[.,]0123$/);
    expect(fmtUsd(12.5)).toMatch(/12[.,]50$/);
    expect(fmtUsd(0)).toMatch(/0[.,]00$/);
  });
});

describe('costText', () => {
  it('says "Not available" only when the source reports it cannot price usage', () => {
    expect(costText(0, false)).toBe(COST_UNAVAILABLE);
    expect(costText(1.5, false)).toBe(COST_UNAVAILABLE);
    expect(costText(1.5, true)).toBe(fmtUsd(1.5));
    expect(costText(0, undefined)).toBe(fmtUsd(0));
  });
});

describe('totalPages', () => {
  it('is at least one', () => {
    expect(totalPages(0, 20)).toBe(1);
    expect(totalPages(20, 20)).toBe(1);
    expect(totalPages(21, 20)).toBe(2);
    expect(totalPages(5, 0)).toBe(1);
  });
});

describe('emptyState', () => {
  const nothing = { title: 'No traces recorded yet', body: 'Once this agent is invoked, each run appears here.' };

  it('says that nothing was recorded only when the API sent no note', () => {
    expect(emptyState([], 'traces', nothing)).toBe(nothing);
    expect(emptyState(null, 'traces', nothing)).toBe(nothing);
    expect(emptyState(undefined, 'traces', nothing)).toBe(nothing);
  });

  it('points at the notes instead when the data may not have been readable', () => {
    const state = emptyState(['There is no reader in this agent’s account, so its traces cannot be read.'], 'traces', nothing);
    expect(state.title).toBe('No traces to show');
    expect(state.body).toMatch(/could not be read or is incomplete/);
    expect(state.body).not.toMatch(/invoked/);
  });
});
