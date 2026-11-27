// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { PublicClientApplication, type Configuration, LogLevel } from '@azure/msal-browser';
import type { EntraConfig } from '../../config/runtimeConfig';
import { AUTH_CALLBACK_PATH } from '../authShape';

const AUTHORITY_HOST = 'https://login.microsoftonline.com';

/** MSAL settings derived from the runtime configuration. Nothing is read at build time. */
export function buildMsalConfiguration(entra: EntraConfig, origin: string): Configuration {
  return {
    auth: {
      clientId: entra.clientId,
      // Single-tenant authority; the multi-tenant /common endpoint is never used.
      authority: `${AUTHORITY_HOST}/${entra.tenantId}`,
      redirectUri: `${origin}${AUTH_CALLBACK_PATH}`,
      postLogoutRedirectUri: origin,
    },
    cache: {
      cacheLocation: 'sessionStorage',
    },
    system: {
      loggerOptions: {
        loggerCallback: (level, message) => {
          if (level === LogLevel.Error) console.error('[MSAL]', message);
          else if (level === LogLevel.Warning) console.warn('[MSAL]', message);
        },
        logLevel: LogLevel.Warning,
        piiLoggingEnabled: false,
      },
    },
  };
}

export function createMsalInstance(entra: EntraConfig, origin: string): PublicClientApplication {
  return new PublicClientApplication(buildMsalConfiguration(entra, origin));
}
