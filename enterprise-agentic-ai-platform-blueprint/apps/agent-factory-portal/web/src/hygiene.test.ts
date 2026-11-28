// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import apiContract from '../API_CONTRACT.md?raw';
import readme from '../README.md?raw';

/**
 * Guards the properties of milestone 1 that are easy to break by accident: the UI is
 * read-only, makes no third-party request, reads no build-time configuration, and every source
 * file carries a licence header.
 */
const sources = import.meta.glob('./**/*.{ts,tsx,css}', { query: '?raw', import: 'default', eager: true }) as Record<
  string,
  string
>;
const SELF = './hygiene.test.ts';
const ACTIONS_CLIENT = './actions/registrationsClient.ts';
const CONTAINMENT_CLIENT = './actions/containmentClient.ts';
const WRITE_CLIENTS = [ACTIONS_CLIENT, CONTAINMENT_CLIENT];
const production = Object.entries(sources).filter(([path]) => !path.endsWith('.test.ts'));
const all = Object.entries(sources).filter(([path]) => path !== SELF);

function offenders(entries: [string, string][], pattern: RegExp): string[] {
  return entries.filter(([, text]) => pattern.test(text)).map(([path]) => path);
}

describe('read-only unless governed actions are on', () => {
  it('finds the source files', () => {
    expect(production.length).toBeGreaterThan(40);
  });

  it('issues writes from the two action clients only', () => {
    expect(offenders(production, /\.(post|put|patch|delete)\s*[<(]/).sort()).toEqual([...WRITE_CLIENTS].sort());
    expect(offenders(production, /method:\s*['"](post|put|patch|delete)['"]/i)).toEqual([]);
    expect(offenders(production, /\.patch\s*[<(]/)).toEqual([]);
  });

  it('writes only to /registrations and to an agent’s containment', () => {
    for (const file of WRITE_CLIENTS) {
      const client = sources[file];
      const targets = [...client.matchAll(/client\.(post|put|delete)(?:<[^>]*>)?\(\s*([^,)]+)/g)].map((m) => m[2].trim());
      expect(targets.length).toBeGreaterThan(0);
      for (const target of targets) {
        expect(target === "'/registrations'" || target.startsWith('path(')).toBe(true);
      }
    }
    expect(sources[ACTIONS_CLIENT]).toContain('const path = (recordId: string, suffix = \'\') => `/registrations/${encodeURIComponent(recordId)}${suffix}`;');
    expect(sources[CONTAINMENT_CLIENT]).toContain(
      'const path = (agentId: string, suffix = \'\') => `/agents/${encodeURIComponent(agentId)}/containment${suffix}`;',
    );
    // The registrations client is the only one that may name a path without the helper.
    expect(sources[CONTAINMENT_CLIENT]).not.toContain("'/registrations'");
  });

  it('keeps the actions feature unreachable unless it is switched on', () => {
    // Nothing outside the folder imports from it statically.
    const outside = production.filter(([path]) => !path.startsWith('./actions/'));
    expect(offenders(outside, /from\s+'[^']*\/actions\//)).toEqual([]);
    // The only ways in are dynamic imports in two files, each rendered behind the flag.
    expect(offenders(outside, /import\('[^']*\/actions\//).sort()).toEqual(['./App.tsx', './components/governance/AgentDetail.tsx']);
    const app = sources['./App.tsx'];
    expect(app).toContain('{governedActions && <Route path="/registrations/*" element={<GovernedActions />} />}');
    expect(app).toContain('{governedActions && <Route path="/approvals" element={<Approvals />} />}');
    expect(app).toContain('const governedActions = config.features.governedActions;');
    const detail = sources['./components/governance/AgentDetail.tsx'];
    expect(detail.match(/<ContainmentTab\b/g)).toHaveLength(1);
    expect(detail).toContain("activeTab.id === 'containment' && governedActions ? (");
    // The registration panel (review and retirement) is the second lazy import, behind the same flag.
    expect(detail.match(/import\('[^']*\/actions\//g)).toHaveLength(2);
    expect(detail.match(/<AgentRegistrationPanel\b/g)).toHaveLength(1);
    expect(detail).toContain('governedActions && registered ? (');
    expect(detail).toContain('const tabs = visibleTabs(agent.origin, { governedActions });');
    // Inside the folder, only the two clients issue requests that write.
    const inside = production.filter(([path]) => path.startsWith('./actions/') && !WRITE_CLIENTS.includes(path));
    expect(offenders(inside, /\.(post|put|patch|delete)\s*[<(]/)).toEqual([]);
  });
});

describe('configuration and credentials', () => {
  it('reads no build-time environment variable', () => {
    expect(offenders(production, /import\.meta\.env|VITE_/)).toEqual([]);
  });

  it('keeps no token in local storage and sends no identity header', () => {
    expect(offenders(production, /localStorage/)).toEqual([]);
    expect(offenders(production, /x-user-email|auth_token/i)).toEqual([]);
  });

  it('imports an identity provider library only inside its own provider folder', () => {
    const msal = offenders(production, /from '@azure\/msal-/).filter((p) => !p.startsWith('./auth/entra/'));
    const oidc = offenders(production, /from 'oidc-client-ts'/).filter((p) => !p.startsWith('./auth/cognito/'));
    expect(msal).toEqual([]);
    expect(oidc).toEqual([]);
  });
});

describe('public-repository hygiene', () => {
  it('makes no request to a third-party host', () => {
    expect(offenders(production, /fonts\.(googleapis|gstatic)\.com|@import\s+url\(/)).toEqual([]);
    expect(offenders(production, /<iframe/i)).toEqual([]);
  });

  it('carries a licence header on every source file', () => {
    const missing = all.filter(([, text]) => !/SPDX-License-Identifier: (Apache-2\.0|MIT-0)/.test(text.slice(0, 400)));
    expect(missing.map(([path]) => path)).toEqual([]);
  });

  it('marks every Apache-2.0 file as derived and modified', () => {
    const unmarked = all.filter(
      ([, text]) =>
        text.slice(0, 400).includes('SPDX-License-Identifier: Apache-2.0') &&
        !text.slice(0, 400).includes('Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.'),
    );
    expect(unmarked.map(([path]) => path)).toEqual([]);
  });

  it('uses no em-dash: an empty value is said in words and prose uses plain punctuation', () => {
    const dash = String.fromCharCode(0x2014);
    expect(all.filter(([, text]) => text.includes(dash)).map(([path]) => path)).toEqual([]);
    expect(readme.includes(dash)).toBe(false);
    expect(apiContract.includes(dash)).toBe(false);
  });

  it('contains no account-shaped number and no absolute local path', () => {
    // The repository's leak guard rejects any twelve digits in a row, even inside a longer
    // number, unless they are one repeated digit (a placeholder account id).
    const accountShaped = (text: string): boolean =>
      [...text.matchAll(/\d{12,}/g)].some(([run]) => {
        for (let i = 0; i + 12 <= run.length; i++) if (new Set(run.slice(i, i + 12)).size > 1) return true;
        return false;
      });
    expect(all.filter(([, text]) => accountShaped(text)).map(([path]) => path)).toEqual([]);
    expect(accountShaped(['17000', '00000', '000'].join(''))).toBe(true);
    expect(accountShaped('1'.repeat(12))).toBe(false);
    expect(offenders(all, /\/(Users|home)\/[a-z]/)).toEqual([]);
  });
});
