// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { createContext, useContext } from 'react';
import type { AuthState } from './authShape';

/**
 * The one context every provider fills. Components read it through `useAuth()` and never
 * import a provider library; the provider is chosen at start-up from the runtime configuration
 * (see `providerSelection.ts`).
 */
export const AuthStateContext = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const ctx = useContext(AuthStateContext);
  if (!ctx) throw new Error('useAuth must be used within an authentication provider');
  return ctx;
}
