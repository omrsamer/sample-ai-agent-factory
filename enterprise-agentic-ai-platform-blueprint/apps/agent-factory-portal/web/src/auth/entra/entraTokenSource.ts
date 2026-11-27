// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import type { AccountInfo, IPublicClientApplication } from '@azure/msal-browser';
import { coalesceAsync } from '../../api/authRetry';
import type { TokenSource } from '../tokenBroker';

function activeAccount(instance: IPublicClientApplication): AccountInfo | null {
  return instance.getActiveAccount() ?? instance.getAllAccounts()[0] ?? null;
}

/**
 * Token source for Microsoft Entra ID: the access token for the API scope, renewed silently
 * from the MSAL cache. `null` when there is no account yet or renewal needs interaction; the
 * provider component owns the interactive fallback, so a background request never starts a
 * redirect.
 */
export function createEntraTokenSource(instance: IPublicClientApplication, scopes: string[]): TokenSource {
  const acquire = async (forceRefresh: boolean): Promise<string | null> => {
    try {
      // Idempotent; covers a request that fires before the provider component has initialised.
      await instance.initialize();
      const account = activeAccount(instance);
      if (!account) return null;
      const result = await instance.acquireTokenSilent({ scopes, account, forceRefresh });
      return result.accessToken;
    } catch {
      return null;
    }
  };
  const cached = coalesceAsync(() => acquire(false));
  const forced = coalesceAsync(() => acquire(true));
  return {
    getToken: (opts) => (opts?.forceRefresh ? forced() : cached()),
  };
}
