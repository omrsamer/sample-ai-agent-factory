// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.

/**
 * Provider-neutral source of the bearer token for API requests.
 *
 * Each authentication provider registers a `TokenSource` when it is loaded; the HTTP client asks
 * this module on every request and never touches a provider library or browser storage itself.
 * With no source registered (before sign-in, or in tests) the answer is `null` and the request
 * goes out without an Authorization header.
 */
export interface TokenSource {
  /**
   * The token to send, or `null` when there is no usable session. `forceRefresh` bypasses any
   * cached token; it is used for the single retry after a 401.
   */
  getToken(opts?: { forceRefresh?: boolean }): Promise<string | null>;
}

let source: TokenSource | null = null;

export function registerTokenSource(next: TokenSource | null): void {
  source = next;
}

export async function currentBearerToken(opts?: { forceRefresh?: boolean }): Promise<string | null> {
  if (!source) return null;
  try {
    return await source.getToken(opts);
  } catch {
    // A token problem must not reject a request before it is sent; the 401 path handles it.
    return null;
  }
}
