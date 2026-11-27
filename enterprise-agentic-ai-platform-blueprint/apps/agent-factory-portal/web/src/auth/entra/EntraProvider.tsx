// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { MsalProvider, useMsal, useIsAuthenticated } from '@azure/msal-react';
import { type AccountInfo, InteractionRequiredAuthError } from '@azure/msal-browser';
import type { RuntimeConfig } from '../../config/runtimeConfig';
import { AUTH_401_COUNT_KEY, safeStorage } from '../../api/authRetry';
import { AuthStateContext } from '../AuthContext';
import type { AuthState } from '../authShape';
import { AUTH_PROVIDER_LABEL, type AuthProviderComponent } from '../providerSelection';
import { registerTokenSource } from '../tokenBroker';
import { createEntraTokenSource } from './entraTokenSource';
import { createMsalInstance } from './msalConfig';

/** Runs inside MsalProvider so it can use the MSAL hooks. */
function EntraAuthInner({ scopes, children }: { scopes: string[]; children: ReactNode }) {
  const { instance, accounts } = useMsal();
  const isAuthenticated = useIsAuthenticated();
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const account: AccountInfo | null = accounts[0] ?? null;

  /**
   * Confirms a token for the API scope can be obtained silently. If the provider needs
   * interaction (consent, a multi-factor challenge), falls through to a redirect.
   */
  const confirmToken = useCallback(async () => {
    if (!account) return;
    try {
      await instance.acquireTokenSilent({ scopes, account });
      safeStorage.remove(AUTH_401_COUNT_KEY);
    } catch (err) {
      if (err instanceof InteractionRequiredAuthError) {
        await instance.acquireTokenRedirect({ scopes, account });
      } else {
        console.error('[auth] silent token acquisition failed');
        setError('Your session could not be renewed. Sign in again.');
      }
    }
  }, [instance, account, scopes]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await instance.initialize();
        await instance.handleRedirectPromise();
      } catch {
        if (!cancelled) setError('Sign-in could not be completed.');
      }
      if (!cancelled) {
        if (account) await confirmToken();
        setIsLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [instance, account, confirmToken]);

  const signInRedirect = useCallback(async () => {
    setError(null);
    await instance.initialize();
    await instance.loginRedirect({ scopes });
  }, [instance, scopes]);

  const signOut = useCallback(() => {
    void (async () => {
      await instance.initialize();
      await instance.logoutRedirect({
        account: account ?? undefined,
        postLogoutRedirectUri: window.location.origin,
      });
    })();
  }, [instance, account]);

  const value: AuthState = {
    isAuthenticated,
    isLoading,
    user: account ? { username: account.username, name: account.name } : null,
    providerLabel: AUTH_PROVIDER_LABEL.entra,
    // MSAL returns to the page that started the sign-in by itself.
    postSignInPath: '/',
    error,
    signInRedirect,
    signOut,
  };
  return <AuthStateContext.Provider value={value}>{children}</AuthStateContext.Provider>;
}

export function createAuthProvider(config: RuntimeConfig): AuthProviderComponent {
  const entra = config.entra;
  if (!entra) throw new Error('The configuration has no "entra" block.');
  const instance = createMsalInstance(entra, window.location.origin);
  const scopes = [entra.apiScope];
  registerTokenSource(createEntraTokenSource(instance, scopes));
  return function EntraProvider({ children }: { children: ReactNode }) {
    return (
      <MsalProvider instance={instance}>
        <EntraAuthInner scopes={scopes}>{children}</EntraAuthInner>
      </MsalProvider>
    );
  };
}
