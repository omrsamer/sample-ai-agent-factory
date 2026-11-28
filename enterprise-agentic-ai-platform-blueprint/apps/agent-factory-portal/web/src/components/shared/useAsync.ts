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
  /** The inputs the result was read for, so a reload can keep showing it. */
  inputs: string;
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
 * after the inputs changed can never be shown against the new inputs. With
 * `keepPreviousOnReload`, a reload of the same inputs keeps showing the last result until the
 * new one arrives, so the screen does not blank while it refreshes.
 */
export function useAsync<T>(
  load: () => Promise<T>,
  deps: readonly (string | number | boolean | null | undefined)[],
  fallbackError: string,
  opts: { keepPreviousOnReload?: boolean } = {},
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
        if (!cancelled) setSettled({ request, inputs, data, error: null, cause: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) setSettled({ request, inputs, data: null, error: errorMessage(err, fallbackError), cause: err });
      });
    return () => {
      cancelled = true;
    };
    // `load` and `fallbackError` are read for the run that `request` identifies.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const current = settled && settled.request === request ? settled : null;
  // While the same inputs are read again, the last result may stay on screen. It is never kept
  // across a change of inputs, so one record is never shown under another's address.
  const previous = opts.keepPreviousOnReload && settled && settled.inputs === inputs ? settled.data : null;
  return {
    data: current ? current.data : previous,
    loading: current === null,
    error: current?.error ?? null,
    cause: current?.cause ?? null,
    reload,
  };
}
