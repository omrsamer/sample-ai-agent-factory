// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it, vi } from 'vitest';
import { createCognitoTokenSource, RENEW_SKEW_SECONDS, type OidcUserLike } from './cognitoTokenSource';

function manager(user: OidcUserLike | null, renewed: OidcUserLike | null | Error = null) {
  return {
    getUser: vi.fn(async () => user),
    signinSilent: vi.fn(async () => {
      if (renewed instanceof Error) throw renewed;
      return renewed;
    }),
  };
}

const FRESH: OidcUserLike = { id_token: 'id-1', expired: false, expires_in: 3000 };

describe('createCognitoTokenSource', () => {
  it('returns the ID token of a live session without renewing', async () => {
    const m = manager(FRESH);
    expect(await createCognitoTokenSource(m).getToken()).toBe('id-1');
    expect(m.signinSilent).not.toHaveBeenCalled();
  });

  it('never returns the access token', async () => {
    const m = manager({ ...FRESH, access_token: 'access-1' } as OidcUserLike);
    expect(await createCognitoTokenSource(m).getToken()).toBe('id-1');
  });

  it('answers null when nobody is signed in, without attempting a renewal', async () => {
    const m = manager(null);
    expect(await createCognitoTokenSource(m).getToken()).toBeNull();
    expect(await createCognitoTokenSource(m).getToken({ forceRefresh: true })).toBeNull();
    expect(m.signinSilent).not.toHaveBeenCalled();
  });

  it('renews an expired session and returns the new ID token', async () => {
    const m = manager({ id_token: 'old', expired: true }, { id_token: 'id-2', expired: false, expires_in: 3600 });
    expect(await createCognitoTokenSource(m).getToken()).toBe('id-2');
    expect(m.signinSilent).toHaveBeenCalledTimes(1);
  });

  it('renews a session that is about to expire', async () => {
    const m = manager({ id_token: 'old', expired: false, expires_in: RENEW_SKEW_SECONDS }, { id_token: 'id-3' });
    expect(await createCognitoTokenSource(m).getToken()).toBe('id-3');
  });

  it('renews on forceRefresh even when the cached token looks live', async () => {
    const m = manager(FRESH, { id_token: 'id-4' });
    expect(await createCognitoTokenSource(m).getToken({ forceRefresh: true })).toBe('id-4');
    expect(m.signinSilent).toHaveBeenCalledTimes(1);
  });

  it('answers null when renewal fails, and does not hand back the stale token', async () => {
    const failing = manager({ id_token: 'stale', expired: true }, new Error('refresh token expired'));
    expect(await createCognitoTokenSource(failing).getToken()).toBeNull();
    const empty = manager({ id_token: 'stale', expired: true }, null);
    expect(await createCognitoTokenSource(empty).getToken()).toBeNull();
  });

  it('shares one renewal across a burst of concurrent requests', async () => {
    const m = manager({ id_token: 'old', expired: true }, { id_token: 'id-5' });
    const source = createCognitoTokenSource(m);
    const tokens = await Promise.all([source.getToken(), source.getToken(), source.getToken({ forceRefresh: true })]);
    expect(tokens).toEqual(['id-5', 'id-5', 'id-5']);
    expect(m.signinSilent).toHaveBeenCalledTimes(1);
  });

  it('renews again for a later request, after the first renewal settled', async () => {
    const m = manager({ id_token: 'old', expired: true }, { id_token: 'id-6' });
    const source = createCognitoTokenSource(m);
    await source.getToken();
    await source.getToken();
    expect(m.signinSilent).toHaveBeenCalledTimes(2);
  });
});
