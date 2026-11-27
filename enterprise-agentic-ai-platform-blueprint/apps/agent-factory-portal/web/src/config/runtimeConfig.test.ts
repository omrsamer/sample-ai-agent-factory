// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it, vi } from 'vitest';
import {
  CONFIG_PATHS,
  getRuntimeConfig,
  isUnusableValue,
  loadRuntimeConfig,
  parseRuntimeConfig,
  setRuntimeConfig,
} from './runtimeConfig';

const COGNITO = {
  authority: 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_EXAMPLE',
  clientId: 'exampleclientid',
  domain: 'https://example-portal.auth.eu-west-1.amazoncognito.com',
  scopes: ['openid', 'email', 'profile'],
};
const ENTRA = {
  tenantId: '1a2b3c4d-1111-4222-8333-a1b2c3d4e5f6',
  clientId: '9f8e7d6c-4444-4555-8666-f6e5d4c3b2a1',
  apiScope: 'api://example-api/access_as_user',
};
const VALID = {
  apiBaseUrl: '/api/v1',
  authProvider: 'cognito',
  cognito: COGNITO,
  environment: 'nonprod',
  features: { readOnly: true },
};

/** An all-zero example GUID, built at run time so no account-shaped literal is in the source. */
const zeroGuid = (last: string) => `00000000-0000-0000-0000-${last.padStart(12, '0')}`;

function ok(raw: unknown) {
  const result = parseRuntimeConfig(raw);
  if ('errors' in result) throw new Error(`expected a config, got: ${result.errors.join(' | ')}`);
  return result.config;
}
function errors(raw: unknown): string[] {
  const result = parseRuntimeConfig(raw);
  return 'errors' in result ? result.errors : [];
}

describe('parseRuntimeConfig', () => {
  it('accepts a Cognito configuration and carries every field', () => {
    expect(ok(VALID)).toEqual({
      apiBaseUrl: '/api/v1',
      authProvider: 'cognito',
      cognito: COGNITO,
      environment: 'nonprod',
      features: { readOnly: true },
    });
  });

  it('accepts an Entra configuration with an absolute API URL', () => {
    const config = ok({ apiBaseUrl: 'https://api.example.com/api/v1/', authProvider: 'entra', entra: ENTRA, environment: 'prod' });
    expect(config.authProvider).toBe('entra');
    expect(config.entra).toEqual(ENTRA);
    expect(config.cognito).toBeUndefined();
    expect(config.environment).toBe('prod');
    expect(config.apiBaseUrl).toBe('https://api.example.com/api/v1');
  });

  it('ignores the block of the provider that is not selected', () => {
    const config = ok({ ...VALID, entra: { tenantId: '<tenantId>', clientId: '', apiScope: '' } });
    expect(config.entra).toBeUndefined();
  });

  it('defaults environment to nonprod, scopes to the OIDC basics and readOnly to true', () => {
    const { scopes: _scopes, ...cognitoWithoutScopes } = COGNITO;
    void _scopes;
    const config = ok({ apiBaseUrl: '/api/v1', authProvider: 'cognito', cognito: cognitoWithoutScopes });
    expect(config.environment).toBe('nonprod');
    expect(config.cognito?.scopes).toEqual(['openid', 'email', 'profile']);
    expect(config.features.readOnly).toBe(true);
  });

  it('turns readOnly off only for an explicit false', () => {
    expect(ok({ ...VALID, features: { readOnly: false } }).features.readOnly).toBe(false);
    expect(ok({ ...VALID, features: { readOnly: 'no' } }).features.readOnly).toBe(true);
    expect(ok({ ...VALID, features: undefined }).features.readOnly).toBe(true);
  });

  it('rejects a non-object', () => {
    expect(errors(null)).toHaveLength(1);
    expect(errors([])).toHaveLength(1);
    expect(errors('text')).toHaveLength(1);
  });

  it('names an unknown or missing authProvider', () => {
    expect(errors({ ...VALID, authProvider: 'saml' })).toContain('authProvider: must be "cognito" or "entra".');
    expect(errors({ apiBaseUrl: '/api/v1' })).toContain('authProvider: must be "cognito" or "entra".');
  });

  it('requires the block of the selected provider', () => {
    expect(errors({ ...VALID, cognito: undefined })).toContain('cognito: required when authProvider is "cognito".');
    expect(errors({ apiBaseUrl: '/api/v1', authProvider: 'entra' })).toContain('entra: required when authProvider is "entra".');
  });

  it('reports every placeholder field by name', () => {
    const found = errors({
      ...VALID,
      cognito: { authority: 'https://cognito-idp.<region>.amazonaws.com/<userPoolId>', clientId: '', domain: undefined },
    });
    expect(found).toEqual([
      'cognito.authority: missing or still a placeholder.',
      'cognito.clientId: missing or still a placeholder.',
      'cognito.domain: missing or still a placeholder.',
    ]);
  });

  it('rejects an all-zero GUID as an Entra tenant or client id', () => {
    const found = errors({
      apiBaseUrl: '/api/v1',
      authProvider: 'entra',
      entra: { ...ENTRA, tenantId: zeroGuid('1') },
    });
    expect(found).toEqual(['entra.tenantId: missing or still a placeholder.']);
  });

  it('requires https for the Cognito authority and domain', () => {
    const found = errors({ ...VALID, cognito: { ...COGNITO, domain: 'http://example-portal.auth.example.com' } });
    expect(found).toEqual(['cognito.domain: must be an https URL.']);
  });

  it('requires the openid scope and a well-formed scope list', () => {
    expect(errors({ ...VALID, cognito: { ...COGNITO, scopes: ['email'] } })).toEqual(['cognito.scopes: must include "openid".']);
    expect(errors({ ...VALID, cognito: { ...COGNITO, scopes: 'openid' } })).toContain(
      'cognito.scopes: must be an array of non-empty strings.',
    );
  });

  it('accepts a same-origin path, https, and loopback http for the API, and nothing else', () => {
    expect(ok({ ...VALID, apiBaseUrl: 'http://localhost:8000/api/v1' }).apiBaseUrl).toBe('http://localhost:8000/api/v1');
    for (const bad of ['http://api.example.com/api/v1', '//evil.example.com/api', 'api/v1', 'javascript:alert(1)']) {
      expect(errors({ ...VALID, apiBaseUrl: bad })).toEqual([
        'apiBaseUrl: must be an https URL or a same-origin path such as "/api/v1".',
      ]);
    }
    expect(errors({ ...VALID, apiBaseUrl: '' })).toEqual(['apiBaseUrl: missing or still a placeholder.']);
  });

  it('rejects an unknown environment', () => {
    expect(errors({ ...VALID, environment: 'staging' })).toEqual(['environment: must be "nonprod" or "prod".']);
  });

  it('never throws, whatever it is given', () => {
    for (const raw of [undefined, 0, { cognito: 1 }, { authProvider: {}, apiBaseUrl: {} }, { ...VALID, cognito: [] }]) {
      expect(() => parseRuntimeConfig(raw)).not.toThrow();
    }
  });
});

describe('isUnusableValue', () => {
  it('treats empty, placeholder, zero-GUID and non-string values as unusable', () => {
    for (const v of ['', '   ', '<clientId>', 'x>y', zeroGuid('2'), undefined, null, 7]) {
      expect(isUnusableValue(v)).toBe(true);
    }
    expect(isUnusableValue('exampleclientid')).toBe(false);
  });
});

function response(body: string, status = 200) {
  return { ok: status >= 200 && status < 300, status, text: async () => body };
}

describe('loadRuntimeConfig', () => {
  it('reads /config.json first and does not touch the local fallback when it is valid', async () => {
    const fetchImpl = vi.fn(async () => response(JSON.stringify(VALID)));
    const result = await loadRuntimeConfig(fetchImpl);
    expect(result).toMatchObject({ ok: true, source: '/config.json' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledWith('/config.json', { cache: 'no-store' });
  });

  it('falls back to /config.local.json when /config.json is missing', async () => {
    const fetchImpl = vi.fn(async (path: string) =>
      path === '/config.json' ? response('not found', 404) : response(JSON.stringify(VALID)),
    );
    const result = await loadRuntimeConfig(fetchImpl);
    expect(result).toMatchObject({ ok: true, source: '/config.local.json' });
    expect(fetchImpl.mock.calls.map((c) => c[0])).toEqual([...CONFIG_PATHS]);
  });

  it('treats an HTML answer with status 200 (a single-page fallback) as a missing file', async () => {
    const fetchImpl = vi.fn(async (path: string) =>
      path === '/config.json' ? response('<!doctype html><html></html>') : response(JSON.stringify(VALID)),
    );
    expect(await loadRuntimeConfig(fetchImpl)).toMatchObject({ ok: true, source: '/config.local.json' });
  });

  it('reports both paths when neither file exists', async () => {
    const result = await loadRuntimeConfig(async () => response('', 404));
    expect(result).toEqual({
      ok: false,
      errors: ['/config.json: not found (HTTP 404).', '/config.local.json: not found (HTTP 404).'],
    });
  });

  it('does not hide an invalid /config.json behind a valid local file', async () => {
    const fetchImpl = vi.fn(async (path: string) =>
      path === '/config.json' ? response(JSON.stringify({ ...VALID, authProvider: 'saml' })) : response(JSON.stringify(VALID)),
    );
    const result = await loadRuntimeConfig(fetchImpl);
    expect(result).toEqual({ ok: false, errors: ['/config.json · authProvider: must be "cognito" or "entra".'] });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('survives a fetch that rejects', async () => {
    const result = await loadRuntimeConfig(async () => {
      throw new Error('network down');
    });
    expect(result).toEqual({
      ok: false,
      errors: ['/config.json: could not be fetched.', '/config.local.json: could not be fetched.'],
    });
  });
});

describe('the active configuration', () => {
  it('is null until the entry point sets it', () => {
    expect(getRuntimeConfig()).toBeNull();
    const config = ok(VALID);
    setRuntimeConfig(config);
    expect(getRuntimeConfig()).toBe(config);
  });
});
