// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { UserManager, WebStorageStateStore, type User } from 'oidc-client-ts';
import type { CognitoConfig, RuntimeConfig } from '../../config/runtimeConfig';
import { AUTH_401_COUNT_KEY, safeStorage } from '../../api/authRetry';
import { AuthStateContext } from '../AuthContext';
import type { AuthState, AuthUser } from '../authShape';
import { AUTH_PROVIDER_LABEL, type AuthProviderComponent } from '../providerSelection';
import { registerTokenSource } from '../tokenBroker';
import {
  buildCognitoLogoutUrl,
  buildCognitoOidcSettings,
  cognitoGroups,
  isSignInCallback,
  safeReturnPath,
} from './cognitoConfig';
import { createCognitoTokenSource } from './cognitoTokenSource';

function toAuthUser(user: User | null): AuthUser | null {
  if (!user || user.expired) return null;
  const profile = user.profile as Record<string, unknown>;
  const email = typeof profile.email === 'string' ? profile.email : undefined;
  return {
    // The token subject and the pool username are opaque identifiers and are never displayed.
    username: email ?? '',
    name: typeof profile.name === 'string' ? profile.name : undefined,
    groups: cognitoGroups(profile),
  };
}

interface Startup {
  user: User | null;
  /** Where the router should go from the callback route. */
  returnPath: string;
}

/**
 * Redeems the authorization response if this page load is the sign-in redirect. The address bar
 * is left alone: the router's callback route replaces it with `returnPath`, which also drops the
 * one-time code and state.
 */
async function completeSignIn(manager: UserManager): Promise<Startup> {
  if (isSignInCallback(window.location.pathname, window.location.search)) {
    const user = await manager.signinRedirectCallback();
    return { user: user ?? null, returnPath: safeReturnPath(user?.state) };
  }
  return { user: await manager.getUser(), returnPath: '/' };
}

function CognitoAuthProvider({
  manager,
  cognito,
  startup,
  children,
}: {
  manager: UserManager;
  cognito: CognitoConfig;
  /** Shared across renders and remounts: an authorization code can be redeemed only once. */
  startup: () => Promise<Startup>;
  children: ReactNode;
}) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [postSignInPath, setPostSignInPath] = useState('/');

  useEffect(() => {
    let cancelled = false;
    startup()
      .then((result) => {
        if (cancelled) return;
        setUser(result.user);
        setPostSignInPath(result.returnPath);
        if (result.user && !result.user.expired) safeStorage.remove(AUTH_401_COUNT_KEY);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setUser(null);
        setError(err instanceof Error ? err.message : 'Sign-in could not be completed.');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    const onLoaded = (loaded: User) => setUser(loaded);
    const onUnloaded = () => setUser(null);
    manager.events.addUserLoaded(onLoaded);
    manager.events.addUserUnloaded(onUnloaded);
    return () => {
      cancelled = true;
      manager.events.removeUserLoaded(onLoaded);
      manager.events.removeUserUnloaded(onUnloaded);
    };
  }, [manager, startup]);

  const signInRedirect = useCallback(async () => {
    setError(null);
    const { pathname, search } = window.location;
    await manager.signinRedirect({ state: safeReturnPath(`${pathname}${search}`) });
  }, [manager]);

  const signOut = useCallback(() => {
    void (async () => {
      try {
        await manager.removeUser();
      } finally {
        window.location.assign(buildCognitoLogoutUrl(cognito, window.location.origin));
      }
    })();
  }, [manager, cognito]);

  const authUser = toAuthUser(user);
  const value: AuthState = {
    isAuthenticated: authUser !== null,
    isLoading,
    user: authUser,
    providerLabel: AUTH_PROVIDER_LABEL.cognito,
    postSignInPath,
    error,
    signInRedirect,
    signOut,
  };
  return <AuthStateContext.Provider value={value}>{children}</AuthStateContext.Provider>;
}

export function createAuthProvider(config: RuntimeConfig): AuthProviderComponent {
  const cognito = config.cognito;
  if (!cognito) throw new Error('The configuration has no "cognito" block.');
  const manager = new UserManager({
    ...buildCognitoOidcSettings(cognito, window.location.origin),
    // Session storage: the session ends with the tab and is not shared across tabs.
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  });
  registerTokenSource(createCognitoTokenSource(manager));
  let startupPromise: Promise<Startup> | null = null;
  const startup = () => (startupPromise ??= completeSignIn(manager));
  return function CognitoProvider({ children }: { children: ReactNode }) {
    return (
      <CognitoAuthProvider manager={manager} cognito={cognito} startup={startup}>
        {children}
      </CognitoAuthProvider>
    );
  };
}
