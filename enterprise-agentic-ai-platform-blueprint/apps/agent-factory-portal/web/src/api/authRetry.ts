// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.

/**
 * Pure helpers behind the HTTP client's handling of 401 responses. Kept free of DOM and network
 * access so they can be unit tested.
 *
 * The policy: an expired token is renewed and the request retried once. If the retry is also
 * refused the page reloads once to sign in again. A second 401 in the same incident is treated
 * as a configuration problem (wrong audience or scope) and reported instead of looping.
 */

/** Session-storage key counting reloads caused by a 401 in the current incident. */
export const AUTH_401_COUNT_KEY = 'afp.auth.401count';

export const AUTH_401_RELOAD_MESSAGE = 'Session expired. Please sign in again.';

export const AUTH_401_HALT_MESSAGE =
  'Sign-in is not working for this deployment. Reloading did not help, so signing in ' +
  'again will not either: a new token is rejected the same way. Ask an administrator ' +
  'to check the sign-in configuration: the token audience, the requested scope, and ' +
  'the app client or app registration the API trusts.';

/** Normalises the stored counter. Anything unreadable counts as zero attempts. */
export function readAttempts(stored: string | null | undefined): number {
  const parsed = Number((stored ?? '').trim());
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 0;
}

/** One reload per incident, then stop. Total: any number is answered. */
export function decide401(attempts: number): 'reload' | 'halt' {
  return attempts >= 1 ? 'halt' : 'reload';
}

/** Wraps an async function so concurrent callers share one in-flight invocation. */
export function coalesceAsync<T>(fn: () => Promise<T>): () => Promise<T> {
  let inFlight: Promise<T> | null = null;
  return () => {
    if (!inFlight) {
      inFlight = fn().finally(() => {
        inFlight = null;
      });
    }
    return inFlight;
  };
}

/**
 * Only a successful response to a request that carried a bearer token proves the token is
 * accepted, so only that clears the 401 counter.
 */
export function clearsAuth401Suspicion(authorizationHeader: unknown): boolean {
  return typeof authorizationHeader === 'string' && authorizationHeader.trim().length > 0;
}

/** Session storage that never throws (private browsing, blocked storage, no DOM). */
export const safeStorage = {
  read(key: string): string | null {
    if (typeof sessionStorage === 'undefined') return null;
    try {
      return sessionStorage.getItem(key);
    } catch {
      return null;
    }
  },

  write(key: string, value: string): void {
    if (typeof sessionStorage === 'undefined') return;
    try {
      sessionStorage.setItem(key, value);
    } catch {
      // Storage is unavailable; the counter degrades to "no attempts recorded".
    }
  },

  remove(key: string): void {
    if (typeof sessionStorage === 'undefined') return;
    try {
      sessionStorage.removeItem(key);
    } catch {
      // Nothing to clear.
    }
  },
};
