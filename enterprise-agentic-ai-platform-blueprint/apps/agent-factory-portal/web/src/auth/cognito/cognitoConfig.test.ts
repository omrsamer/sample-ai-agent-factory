// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import {
  buildCognitoLogoutUrl,
  buildCognitoOidcSettings,
  cognitoGroups,
  isSignInCallback,
  safeReturnPath,
} from './cognitoConfig';

const COGNITO = {
  authority: 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_EXAMPLE',
  clientId: 'example client&id',
  domain: 'https://example-portal.auth.eu-west-1.amazoncognito.com',
  scopes: ['openid', 'email', 'profile'],
};
const ORIGIN = 'https://portal.example.com';

describe('buildCognitoOidcSettings', () => {
  it('requests the authorization code flow against the user pool issuer', () => {
    expect(buildCognitoOidcSettings(COGNITO, ORIGIN)).toEqual({
      authority: COGNITO.authority,
      client_id: COGNITO.clientId,
      redirect_uri: 'https://portal.example.com/auth/callback',
      response_type: 'code',
      scope: 'openid email profile',
      automaticSilentRenew: false,
      loadUserInfo: false,
    });
  });
});

describe('buildCognitoLogoutUrl', () => {
  it('targets the hosted UI /logout endpoint with client_id and logout_uri', () => {
    const url = new URL(buildCognitoLogoutUrl(COGNITO, ORIGIN));
    expect(`${url.origin}${url.pathname}`).toBe('https://example-portal.auth.eu-west-1.amazoncognito.com/logout');
    expect(url.searchParams.get('client_id')).toBe(COGNITO.clientId);
    expect(url.searchParams.get('logout_uri')).toBe('https://portal.example.com/');
    expect([...url.searchParams.keys()]).toEqual(['client_id', 'logout_uri']);
  });

  it('encodes both parameters', () => {
    const url = buildCognitoLogoutUrl(COGNITO, ORIGIN);
    expect(url).toContain('client_id=example+client%26id');
    expect(url).toContain('logout_uri=https%3A%2F%2Fportal.example.com%2F');
  });
});

describe('cognitoGroups', () => {
  it('reads the cognito:groups claim', () => {
    expect(cognitoGroups({ 'cognito:groups': ['platform-engineering', 'finops'] })).toEqual(['platform-engineering', 'finops']);
  });

  it('answers an empty list for a missing or malformed claim', () => {
    expect(cognitoGroups(undefined)).toEqual([]);
    expect(cognitoGroups({})).toEqual([]);
    expect(cognitoGroups({ 'cognito:groups': 'admins' })).toEqual([]);
    expect(cognitoGroups({ 'cognito:groups': ['ok', 7, '', null] })).toEqual(['ok']);
  });
});

describe('isSignInCallback', () => {
  it('is true only on the callback path with a state and a code or an error', () => {
    expect(isSignInCallback('/auth/callback', '?code=abc&state=xyz')).toBe(true);
    expect(isSignInCallback('/auth/callback', '?error=access_denied&state=xyz')).toBe(true);
    expect(isSignInCallback('/auth/callback', '?code=abc')).toBe(false);
    expect(isSignInCallback('/auth/callback', '')).toBe(false);
    expect(isSignInCallback('/agents', '?code=abc&state=xyz')).toBe(false);
  });
});

describe('safeReturnPath', () => {
  it('keeps an in-app path with its query', () => {
    expect(safeReturnPath('/agents/a-1?tab=cost')).toBe('/agents/a-1?tab=cost');
    expect(safeReturnPath('/')).toBe('/');
  });

  it('falls back to the home page for anything that could leave the origin', () => {
    for (const raw of ['https://evil.example.com/', '//evil.example.com', '/\\evil.example.com', 'agents', '', null, undefined, 7, {}]) {
      expect(safeReturnPath(raw)).toBe('/');
    }
  });

  it('never returns to the callback path itself', () => {
    expect(safeReturnPath('/auth/callback')).toBe('/');
    expect(safeReturnPath('/auth/callback?code=x&state=y')).toBe('/');
  });
});
