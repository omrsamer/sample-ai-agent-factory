// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.

/**
 * What an authentication provider exposes through `useAuth()`.
 *
 * The portal never manages credentials itself: sign-in and sign-out are redirects to the
 * configured identity provider. Tokens are not part of this shape; API calls obtain them from
 * `tokenBroker.ts`.
 */
export interface AuthUser {
  username: string;
  name?: string;
  /** Identity provider groups, for display only. The back end decides the caller's role. */
  groups?: string[];
}

export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: AuthUser | null;
  /** Human-readable provider name, used on the sign-in button. */
  providerLabel: string;
  /** The in-app path to open after the sign-in redirect: the page the user asked for, or `/`. */
  postSignInPath: string;
  /** A sign-in or session error worth showing on the sign-in page. */
  error: string | null;
  /** Starts the hosted sign-in redirect. */
  signInRedirect: () => Promise<void>;
  /** Clears the local session and redirects to the provider's sign-out endpoint. */
  signOut: () => void;
}

/** Path both providers use as the redirect target after sign-in. */
export const AUTH_CALLBACK_PATH = '/auth/callback';
