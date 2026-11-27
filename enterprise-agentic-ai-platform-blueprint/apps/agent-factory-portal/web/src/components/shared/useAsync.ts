// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useCallback, useEffect, useMemo, useState } from 'react';
import { errorMessage } from './ui';

export interface AsyncState<T> {
  /** The result of the current read, or null while it is loading or after it failed. */
  data: T | null;
  loading: boolean;
  error: string | null;
  /** The failure itself, for callers that need the HTTP status. */
  cause: unknown;
  reload: () => void;
}

interface Settled<T> {
  request: object;
  data: T | null;
  error: string | null;
  cause: unknown;
}

/**
 * Runs a read when the component mounts and whenever `deps` change. `deps` lists the inputs of
 * `load` and must hold only strings, numbers, booleans, null or undefined: they are compared by
 * their JSON form.
 *
 * Each run is identified by a request token. A result is stored with the token of the run that
 * produced it, and only the result of the current run is exposed, so a response that arrives
 * after the inputs changed can never be shown against the new inputs.
 */
export function useAsync<T>(
  load: () => Promise<T>,
  deps: readonly (string | number | boolean | null | undefined)[],
  fallbackError: string,
): AsyncState<T> {
  const [nonce, setNonce] = useState(0);
  // A new token whenever an input or the reload counter changes.
  const inputs = JSON.stringify(deps);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const request = useMemo(() => ({}), [inputs, nonce]);
  const [settled, setSettled] = useState<Settled<T> | null>(null);

  useEffect(() => {
    let cancelled = false;
    load()
      .then((data) => {
        if (!cancelled) setSettled({ request, data, error: null, cause: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) setSettled({ request, data: null, error: errorMessage(err, fallbackError), cause: err });
      });
    return () => {
      cancelled = true;
    };
    // `load` and `fallbackError` are read for the run that `request` identifies.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const current = settled && settled.request === request ? settled : null;
  return {
    data: current?.data ?? null,
    loading: current === null,
    error: current?.error ?? null,
    cause: current?.cause ?? null,
    reload,
  };
}
