// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { AxiosError, type AxiosAdapter, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import client, {
  ApiRequestError,
  agentMcpGrantsApi,
  agentOpsApi,
  agentsApi,
  catalogApi,
  configureApiClient,
  fleetApi,
  formatApiErrorDetail,
  governanceGraphApi,
  guardrailsApi,
  isNotFound,
  mcpServersApi,
  observabilityApi,
  userApi,
} from './client';
import { AUTH_401_RELOAD_MESSAGE } from './authRetry';
import { registerTokenSource } from '../auth/tokenBroker';

describe('formatApiErrorDetail', () => {
  it('passes a plain string detail through unchanged', () => {
    expect(formatApiErrorDetail('Agent not found', 'fallback')).toBe('Agent not found');
  });

  it('falls back to the given message when detail is missing or empty', () => {
    expect(formatApiErrorDetail(undefined, 'network error')).toBe('network error');
    expect(formatApiErrorDetail('', 'network error')).toBe('network error');
    expect(formatApiErrorDetail([], 'network error')).toBe('network error');
  });

  it('joins a validation-error list into field: message text', () => {
    const detail = [
      { loc: ['query', 'date_from'], msg: 'invalid date' },
      { loc: ['query', 'limit'], msg: 'must be positive' },
    ];
    expect(formatApiErrorDetail(detail, 'fallback')).toBe('date_from: invalid date; limit: must be positive');
  });

  it('uses the bare message when loc has no field segment', () => {
    expect(formatApiErrorDetail([{ loc: ['body'], msg: 'malformed request' }], 'fallback')).toBe('malformed request');
  });
});

describe('the endpoints the portal calls', () => {
  afterEach(() => vi.restoreAllMocks());

  it('calls exactly the documented GET paths, relative to the API base', async () => {
    const get = vi.spyOn(client, 'get').mockResolvedValue({ data: {} });
    await userApi.getCurrentUser();
    await agentsApi.list({ lifecycle_state: 'approved' });
    await agentsApi.get('a 1');
    await agentOpsApi.runtime('a1', { stage: 'prod' });
    await agentOpsApi.deployments('a1', { limit: 25 });
    await agentOpsApi.evalRuns('a1');
    await agentMcpGrantsApi.list('a1');
    await observabilityApi.getAgentTraces('a1', { page: 2, limit: 20 });
    await observabilityApi.getAgentMetrics('a1', { dateFrom: '2026-01-01', dateTo: '2026-01-31' });
    await mcpServersApi.list();
    await mcpServersApi.get('m1');
    await mcpServersApi.policies('m1');
    await mcpServersApi.policyEnforcement('m1');
    await mcpServersApi.connectedAgents('m1');
    await governanceGraphApi.get();
    await governanceGraphApi.principal('p/1', 'group');
    await observabilityApi.getSettings();
    await observabilityApi.getMetrics('tenant', { dateFrom: '2026-01-01', dateTo: '2026-01-31' });
    await guardrailsApi.list();
    await guardrailsApi.get('g1');
    await fleetApi.health();
    await catalogApi.models();
    await catalogApi.tools();

    expect(get.mock.calls.map((c) => c[0])).toEqual([
      '/users/me',
      '/agents',
      '/agents/a%201',
      '/agents/a1/runtime',
      '/agents/a1/deployments',
      '/agents/a1/evals/runs',
      '/agents/a1/mcp-grants',
      '/agents/a1/traces',
      '/agents/a1/metrics',
      '/mcp-servers',
      '/mcp-servers/m1',
      '/mcp-servers/m1/policies',
      '/mcp-servers/m1/policy-enforcement',
      '/mcp-servers/m1/grants',
      '/governance-graph',
      '/principals/p%2F1',
      '/observability/settings',
      '/observability/metrics',
      '/guardrails',
      '/guardrails/g1',
      '/fleet/health',
      '/catalog/models',
      '/catalog/tools',
    ]);
  });

  it('sends the documented query parameters', async () => {
    const get = vi.spyOn(client, 'get').mockResolvedValue({ data: {} });
    await agentsApi.list({ lifecycle_state: 'approved' });
    await agentOpsApi.runtime('a1', { stage: 'prod' });
    await agentOpsApi.deployments('a1', { stage: 'prod', limit: 25 });
    await observabilityApi.getAgentTraces('a1', { page: 2, limit: 20 });
    await observabilityApi.getAgentMetrics('a1', { dateFrom: '2026-01-01', dateTo: '2026-01-31' });
    await observabilityApi.getMetrics('platform', { dateFrom: '2026-01-01', dateTo: '2026-01-31' });
    await governanceGraphApi.principal('p1', 'user');
    expect(get.mock.calls.map((c) => (c[1] as { params?: unknown } | undefined)?.params)).toEqual([
      { lifecycle_state: 'approved' },
      { stage: 'prod' },
      { stage: 'prod', limit: 25 },
      { page: 2, limit: 20 },
      { date_from: '2026-01-01', date_to: '2026-01-31' },
      { scope: 'platform', date_from: '2026-01-01', date_to: '2026-01-31' },
      { kind: 'user' },
    ]);
  });
});

describe('request and 401 handling', () => {
  const originalAdapter = client.defaults.adapter;
  let seen: InternalAxiosRequestConfig[];
  // Recorded at call time: a retry reuses and mutates the same request config object.
  let authHeaders: unknown[];

  function respondWith(statuses: number[], body: unknown = { detail: 'Agent not found' }) {
    const queue = [...statuses];
    const adapter: AxiosAdapter = async (config) => {
      seen.push(config);
      authHeaders.push(config.headers.Authorization);
      const status = queue.shift() ?? 200;
      const response = { data: status === 200 ? { ok: true } : body, status, statusText: '', headers: {}, config };
      if (status >= 200 && status < 300) return response;
      throw new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_REQUEST', config, null, response);
    };
    client.defaults.adapter = adapter;
  }

  beforeEach(() => {
    seen = [];
    authHeaders = [];
    configureApiClient('https://api.example.com/api/v1');
  });
  afterEach(() => {
    client.defaults.adapter = originalAdapter;
    registerTokenSource(null);
  });

  it('uses the configured base URL and the bearer token from the token broker', async () => {
    registerTokenSource({ getToken: async () => 'cached-token' });
    respondWith([200]);
    await agentsApi.list();
    expect(seen).toHaveLength(1);
    expect(seen[0].baseURL).toBe('https://api.example.com/api/v1');
    expect(seen[0].url).toBe('/agents');
    expect(seen[0].method).toBe('get');
    expect(seen[0].headers.Authorization).toBe('Bearer cached-token');
  });

  it('sends no Authorization header and no identity header when there is no session', async () => {
    respondWith([200]);
    await agentsApi.list();
    expect(seen[0].headers.Authorization).toBeUndefined();
    expect(Object.keys(seen[0].headers).map((h) => h.toLowerCase())).not.toContain('x-user-email');
  });

  it('retries a 401 once with a force-refreshed token', async () => {
    const getToken = vi.fn(async (opts?: { forceRefresh?: boolean }) => (opts?.forceRefresh ? 'fresh-token' : 'stale-token'));
    registerTokenSource({ getToken });
    respondWith([401, 200]);
    await expect(agentsApi.list()).resolves.toEqual({ ok: true });
    expect(authHeaders).toEqual(['Bearer stale-token', 'Bearer fresh-token']);
    expect(getToken).toHaveBeenCalledWith({ forceRefresh: true });
  });

  it('does not retry a second time when the refreshed token is also refused', async () => {
    registerTokenSource({ getToken: async (opts) => (opts?.forceRefresh ? 'fresh-token' : 'stale-token') });
    respondWith([401, 401, 200]);
    const failure = await agentsApi.list().catch((e: unknown) => e);
    expect(authHeaders).toEqual(['Bearer stale-token', 'Bearer fresh-token']);
    expect(failure).toBeInstanceOf(ApiRequestError);
    expect((failure as ApiRequestError).status).toBe(401);
    expect((failure as ApiRequestError).message).toBe(AUTH_401_RELOAD_MESSAGE);
  });

  it('reports other failures with the API detail and the status', async () => {
    respondWith([404]);
    const failure = await agentsApi.get('missing').catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(ApiRequestError);
    expect((failure as ApiRequestError).message).toBe('Agent not found');
    expect(isNotFound(failure)).toBe(true);
    respondWith([500], { detail: 'boom' });
    expect(isNotFound(await agentsApi.list().catch((e: unknown) => e))).toBe(false);
  });
});
