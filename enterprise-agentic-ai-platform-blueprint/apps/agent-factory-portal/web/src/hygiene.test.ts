// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';

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
const production = Object.entries(sources).filter(([path]) => !path.endsWith('.test.ts'));
const all = Object.entries(sources).filter(([path]) => path !== SELF);

function offenders(entries: [string, string][], pattern: RegExp): string[] {
  return entries.filter(([, text]) => pattern.test(text)).map(([path]) => path);
}

describe('milestone 1 is read-only', () => {
  it('finds the source files', () => {
    expect(production.length).toBeGreaterThan(40);
  });

  it('issues no mutating HTTP request', () => {
    expect(offenders(production, /\.(post|put|patch|delete)\s*[<(]/)).toEqual([]);
    expect(offenders(production, /method:\s*['"](post|put|patch|delete)['"]/i)).toEqual([]);
  });

  it('uses no blocking browser dialog', () => {
    expect(offenders(production, /\b(window\.)?(confirm|prompt|alert)\s*\(/)).toEqual([]);
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

  it('contains no account-shaped number and no absolute local path', () => {
    expect(offenders(all, /(?<![\d.])\d{12}(?![\d.])/)).toEqual([]);
    expect(offenders(all, /\/(Users|home)\/[a-z]/)).toEqual([]);
  });
});
