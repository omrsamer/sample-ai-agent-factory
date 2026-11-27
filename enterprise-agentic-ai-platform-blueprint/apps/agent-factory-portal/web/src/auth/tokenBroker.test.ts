// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, describe, expect, it, vi } from 'vitest';
import { currentBearerToken, registerTokenSource } from './tokenBroker';

afterEach(() => registerTokenSource(null));

describe('currentBearerToken', () => {
  it('answers null when no provider has registered a source', async () => {
    expect(await currentBearerToken()).toBeNull();
  });

  it('asks the registered source, whichever provider registered it', async () => {
    const getToken = vi.fn(async (opts?: { forceRefresh?: boolean }) => (opts?.forceRefresh ? 'fresh' : 'cached'));
    registerTokenSource({ getToken });
    expect(await currentBearerToken()).toBe('cached');
    expect(await currentBearerToken({ forceRefresh: true })).toBe('fresh');
    expect(getToken).toHaveBeenNthCalledWith(1, undefined);
    expect(getToken).toHaveBeenNthCalledWith(2, { forceRefresh: true });
  });

  it('turns a throwing source into null instead of rejecting the request', async () => {
    registerTokenSource({
      getToken: async () => {
        throw new Error('provider exploded');
      },
    });
    await expect(currentBearerToken()).resolves.toBeNull();
  });

  it('uses the most recently registered source', async () => {
    registerTokenSource({ getToken: async () => 'first' });
    registerTokenSource({ getToken: async () => 'second' });
    expect(await currentBearerToken()).toBe('second');
  });
});
