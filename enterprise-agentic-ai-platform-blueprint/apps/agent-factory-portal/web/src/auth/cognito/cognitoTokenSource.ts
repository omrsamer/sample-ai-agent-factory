// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { coalesceAsync } from '../../api/authRetry';
import type { TokenSource } from '../tokenBroker';

/** The part of an oidc-client-ts `User` this module reads. */
export interface OidcUserLike {
  id_token?: string;
  expired?: boolean;
  /** Seconds until the access token expires. */
  expires_in?: number;
}

/** The part of an oidc-client-ts `UserManager` this module calls. */
export interface OidcManagerLike {
  getUser(): Promise<OidcUserLike | null>;
  /** Uses the refresh token when the session has one. */
  signinSilent(): Promise<OidcUserLike | null>;
}

/** Renew this many seconds before expiry, so a request never leaves with a dying token. */
export const RENEW_SKEW_SECONDS = 60;

function needsRenewal(user: OidcUserLike): boolean {
  if (user.expired) return true;
  return typeof user.expires_in === 'number' && user.expires_in <= RENEW_SKEW_SECONDS;
}

/**
 * Token source for Amazon Cognito.
 *
 * Returns the ID token, not the access token: the API's JWT authorizer validates the app client
 * id as the audience, and only the ID token carries it in `aud`.
 *
 * Renewal is coalesced, so a burst of requests on an expired session triggers one refresh. A
 * failed refresh answers `null`; this module never starts a redirect on its own.
 */
export function createCognitoTokenSource(manager: OidcManagerLike): TokenSource {
  const renew = coalesceAsync(async (): Promise<string | null> => {
    try {
      const renewed = await manager.signinSilent();
      return renewed?.id_token ?? null;
    } catch {
      return null;
    }
  });

  return {
    async getToken(opts) {
      const user = await manager.getUser();
      if (!user) return null;
      if (opts?.forceRefresh || needsRenewal(user)) return renew();
      return user.id_token ?? null;
    },
  };
}
