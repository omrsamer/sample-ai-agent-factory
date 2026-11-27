// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it, vi } from 'vitest';
import type { RuntimeConfig } from '../config/runtimeConfig';
import { AUTH_PROVIDER_LABEL, loadAuthProvider, type AuthProviderComponent } from './providerSelection';

const BASE = { apiBaseUrl: '/api/v1', environment: 'nonprod', features: { readOnly: true } } as const;
const COGNITO_CONFIG: RuntimeConfig = {
  ...BASE,
  authProvider: 'cognito',
  cognito: { authority: 'https://issuer.example.com/pool', clientId: 'c', domain: 'https://auth.example.com', scopes: ['openid'] },
};
const ENTRA_CONFIG: RuntimeConfig = {
  ...BASE,
  authProvider: 'entra',
  entra: { tenantId: 't', clientId: 'c', apiScope: 'api://example/access_as_user' },
};

function loaders() {
  const CognitoProvider: AuthProviderComponent = () => null;
  const EntraProvider: AuthProviderComponent = () => null;
  const createCognito = vi.fn(() => CognitoProvider);
  const createEntra = vi.fn(() => EntraProvider);
  return {
    CognitoProvider,
    EntraProvider,
    createCognito,
    createEntra,
    table: {
      cognito: vi.fn(async () => ({ createAuthProvider: createCognito })),
      entra: vi.fn(async () => ({ createAuthProvider: createEntra })),
    },
  };
}

describe('loadAuthProvider', () => {
  it('loads only the Cognito module for authProvider "cognito"', async () => {
    const l = loaders();
    expect(await loadAuthProvider(COGNITO_CONFIG, l.table)).toBe(l.CognitoProvider);
    expect(l.table.cognito).toHaveBeenCalledTimes(1);
    expect(l.table.entra).not.toHaveBeenCalled();
    expect(l.createCognito).toHaveBeenCalledWith(COGNITO_CONFIG);
  });

  it('loads only the Entra module for authProvider "entra"', async () => {
    const l = loaders();
    expect(await loadAuthProvider(ENTRA_CONFIG, l.table)).toBe(l.EntraProvider);
    expect(l.table.entra).toHaveBeenCalledTimes(1);
    expect(l.table.cognito).not.toHaveBeenCalled();
    expect(l.createEntra).toHaveBeenCalledWith(ENTRA_CONFIG);
  });

  it('rejects, without loading anything, when the selected block is absent', async () => {
    const l = loaders();
    const broken = { ...BASE, authProvider: 'cognito' } as RuntimeConfig;
    await expect(loadAuthProvider(broken, l.table)).rejects.toThrow('no "cognito" block');
    expect(l.table.cognito).not.toHaveBeenCalled();
    expect(l.table.entra).not.toHaveBeenCalled();
  });

  it('does not fall back to the other provider when it is also configured', async () => {
    const l = loaders();
    const both: RuntimeConfig = { ...ENTRA_CONFIG, cognito: COGNITO_CONFIG.cognito };
    expect(await loadAuthProvider(both, l.table)).toBe(l.EntraProvider);
    expect(l.table.cognito).not.toHaveBeenCalled();
  });

  it('rejects an unsupported provider name', async () => {
    const l = loaders();
    const odd = { ...BASE, authProvider: 'saml', saml: {} } as unknown as RuntimeConfig;
    await expect(loadAuthProvider(odd, l.table)).rejects.toThrow('Unsupported authProvider "saml"');
  });
});

describe('AUTH_PROVIDER_LABEL', () => {
  it('names each provider for the sign-in button', () => {
    expect(AUTH_PROVIDER_LABEL).toEqual({ cognito: 'Amazon Cognito', entra: 'Microsoft Entra ID' });
  });
});
