// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { ComponentType, ReactNode } from 'react';
import type { AuthProviderName, RuntimeConfig } from '../config/runtimeConfig';

export type AuthProviderComponent = ComponentType<{ children: ReactNode }>;

export const AUTH_PROVIDER_LABEL: Record<AuthProviderName, string> = {
  cognito: 'Amazon Cognito',
  entra: 'Microsoft Entra ID',
};

export interface AuthProviderModule {
  /** Builds the provider component and registers its token source. */
  createAuthProvider: (config: RuntimeConfig) => AuthProviderComponent;
}

type Loaders = Record<AuthProviderName, () => Promise<AuthProviderModule>>;

/**
 * Dynamic imports, so a deployment downloads only the library of the provider it uses and the
 * rest of the application never imports one.
 */
export const DEFAULT_LOADERS: Loaders = {
  cognito: () => import('./cognito/CognitoProvider'),
  entra: () => import('./entra/EntraProvider'),
};

/** Resolves the provider named by `config.authProvider`. Rejects if its block is absent. */
export async function loadAuthProvider(
  config: RuntimeConfig,
  loaders: Loaders = DEFAULT_LOADERS,
): Promise<AuthProviderComponent> {
  const name = config.authProvider;
  if (!config[name]) {
    throw new Error(`authProvider is "${name}" but the configuration has no "${name}" block.`);
  }
  const load = loaders[name];
  if (!load) throw new Error(`Unsupported authProvider "${String(name)}".`);
  const module = await load();
  return module.createAuthProvider(config);
}
