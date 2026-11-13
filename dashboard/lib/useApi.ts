"use client";

import { useCallback, useEffect, useState } from "react";
import { getJSON } from "./api";

export interface ApiState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  refetch: () => void;
}

/** Fetches `path` whenever it changes. `path` null means "do not fetch yet". */
export function useApi<T>(path: string | null): ApiState<T> {
  const [version, setVersion] = useState(0);
  const [state, setState] = useState<Omit<ApiState<T>, "refetch">>({
    data: null,
    error: null,
    loading: path !== null,
  });

  useEffect(() => {
    if (path === null) {
      setState({ data: null, error: null, loading: false });
      return;
    }
    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));
    getJSON<T>(path)
      .then((data) => !cancelled && setState({ data, error: null, loading: false }))
      .catch((err: Error) => !cancelled && setState({ data: null, error: err.message, loading: false }));
    return () => {
      cancelled = true;
    };
  }, [path, version]);

  const refetch = useCallback(() => setVersion((v) => v + 1), []);
  return { ...state, refetch };
}
