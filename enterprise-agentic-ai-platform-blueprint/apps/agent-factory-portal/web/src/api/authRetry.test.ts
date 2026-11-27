// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AUTH_401_COUNT_KEY,
  AUTH_401_HALT_MESSAGE,
  AUTH_401_RELOAD_MESSAGE,
  clearsAuth401Suspicion,
  coalesceAsync,
  decide401,
  readAttempts,
  safeStorage,
} from './authRetry';

describe('decide401', () => {
  it('reloads on the first 401 of an incident and halts on the second', () => {
    expect(decide401(0)).toBe('reload');
    expect(decide401(1)).toBe('halt');
    expect(decide401(7)).toBe('halt');
  });

  it('answers for any number', () => {
    for (const n of [-1, Number.NaN, Number.POSITIVE_INFINITY, 0.5]) {
      expect(['reload', 'halt']).toContain(decide401(n));
    }
    expect(decide401(Number.NaN)).toBe('reload');
  });
});

describe('readAttempts', () => {
  it('reads a stored counter, tolerating padding and fractions', () => {
    expect(readAttempts('1')).toBe(1);
    expect(readAttempts(' 2 ')).toBe(2);
    expect(readAttempts('1.9')).toBe(1);
  });

  it('treats anything unreadable as zero', () => {
    for (const v of [null, undefined, '', 'abc', '-3', 'NaN', 'Infinity']) {
      expect(readAttempts(v)).toBe(0);
    }
  });

  it('composes with decide401', () => {
    expect(decide401(readAttempts(null))).toBe('reload');
    expect(decide401(readAttempts('1'))).toBe('halt');
  });
});

describe('coalesceAsync', () => {
  it('runs once for a burst of concurrent callers', async () => {
    const fn = vi.fn(async () => 'token');
    const shared = coalesceAsync(fn);
    expect(await Promise.all([shared(), shared(), shared()])).toEqual(['token', 'token', 'token']);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('runs again once the in-flight call has settled', async () => {
    const fn = vi.fn(async () => 'token');
    const shared = coalesceAsync(fn);
    await shared();
    await shared();
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('clears the slot after a rejection, and shares the rejection across the burst', async () => {
    const fn = vi.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce('ok');
    const shared = coalesceAsync(fn as () => Promise<string>);
    const burst = await Promise.allSettled([shared(), shared()]);
    expect(burst.map((r) => r.status)).toEqual(['rejected', 'rejected']);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(await shared()).toBe('ok');
  });
});

describe('the messages', () => {
  it('uses the portal key, not a shared or legacy one', () => {
    expect(AUTH_401_COUNT_KEY).toBe('afp.auth.401count');
  });

  it('tells an expired session to sign in again', () => {
    expect(AUTH_401_RELOAD_MESSAGE).toBe('Session expired. Please sign in again.');
  });

  it('says the halt is a configuration problem and leaks no token, id or URL', () => {
    expect(AUTH_401_HALT_MESSAGE).toMatch(/sign-in configuration/);
    expect(AUTH_401_HALT_MESSAGE).toMatch(/audience/);
    expect(AUTH_401_HALT_MESSAGE).not.toMatch(/https?:\/\//);
    expect(AUTH_401_HALT_MESSAGE).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}/i);
  });
});

describe('clearsAuth401Suspicion', () => {
  it('accepts only a non-empty Authorization header', () => {
    expect(clearsAuth401Suspicion('Bearer abc')).toBe(true);
    for (const v of [undefined, null, '', '   ', 0, {}, ['Bearer abc']]) {
      expect(clearsAuth401Suspicion(v)).toBe(false);
    }
  });
});

describe('safeStorage', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('never throws when there is no storage at all', () => {
    expect(typeof sessionStorage).toBe('undefined');
    expect(safeStorage.read('k')).toBeNull();
    expect(() => safeStorage.write('k', 'v')).not.toThrow();
    expect(() => safeStorage.remove('k')).not.toThrow();
  });

  it('round-trips through a working storage', () => {
    const store = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    });
    safeStorage.write('k', '1');
    expect(safeStorage.read('k')).toBe('1');
    safeStorage.remove('k');
    expect(safeStorage.read('k')).toBeNull();
  });

  it('never throws when storage throws', () => {
    const blocked = () => {
      throw new Error('SecurityError');
    };
    vi.stubGlobal('sessionStorage', { getItem: blocked, setItem: blocked, removeItem: blocked });
    expect(safeStorage.read('k')).toBeNull();
    expect(() => safeStorage.write('k', 'v')).not.toThrow();
    expect(() => safeStorage.remove('k')).not.toThrow();
  });
});
