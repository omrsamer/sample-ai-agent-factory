// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { CognitoConfig } from '../../config/runtimeConfig';
import { AUTH_CALLBACK_PATH } from '../authShape';

/** The subset of oidc-client-ts settings the portal sets. Kept pure so it can be unit tested. */
export interface CognitoOidcSettings {
  authority: string;
  client_id: string;
  redirect_uri: string;
  response_type: 'code';
  scope: string;
  automaticSilentRenew: boolean;
  loadUserInfo: boolean;
}

/**
 * Authorization code flow with PKCE (the library's default for `response_type: 'code'`)
 * against the user pool's OIDC issuer. Renewal is driven by the token source on demand rather
 * than by a timer, so an idle tab makes no background calls.
 */
export function buildCognitoOidcSettings(cognito: CognitoConfig, origin: string): CognitoOidcSettings {
  return {
    authority: cognito.authority,
    client_id: cognito.clientId,
    redirect_uri: `${origin}${AUTH_CALLBACK_PATH}`,
    response_type: 'code',
    scope: cognito.scopes.join(' '),
    automaticSilentRenew: false,
    loadUserInfo: false,
  };
}

/**
 * Cognito does not publish an `end_session_endpoint`, so sign-out goes to the hosted UI's
 * `/logout` endpoint. `logout_uri` must be registered as a sign-out URL on the app client.
 */
export function buildCognitoLogoutUrl(cognito: CognitoConfig, origin: string): string {
  const params = new URLSearchParams({ client_id: cognito.clientId, logout_uri: `${origin}/` });
  return `${cognito.domain}/logout?${params.toString()}`;
}

/** Reads the `cognito:groups` claim. For display only; the back end decides the role. */
export function cognitoGroups(profile: Record<string, unknown> | null | undefined): string[] {
  const raw = profile?.['cognito:groups'];
  if (!Array.isArray(raw)) return [];
  return raw.filter((g): g is string => typeof g === 'string' && g.trim() !== '');
}

/**
 * Where to land after sign-in: the in-app path the user asked for. Only a same-origin path is
 * accepted, so a crafted value cannot turn the sign-in redirect into an open redirect.
 */
export function safeReturnPath(raw: unknown): string {
  if (typeof raw !== 'string') return '/';
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) return '/';
  if (raw === AUTH_CALLBACK_PATH || raw.startsWith(`${AUTH_CALLBACK_PATH}?`)) return '/';
  return raw;
}

/** True when the current URL is the sign-in redirect carrying an authorization response. */
export function isSignInCallback(pathname: string, search: string): boolean {
  if (pathname !== AUTH_CALLBACK_PATH) return false;
  const params = new URLSearchParams(search);
  return params.has('state') && (params.has('code') || params.has('error'));
}
