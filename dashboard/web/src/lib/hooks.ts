import { useCallback, useEffect, useRef, useState } from "react";
import { get } from "../api";

export interface Loadable<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/** Fetch ``path`` (skipped when null); refetches when the path changes. */
export function useApi<T>(path: string | null, pollMs?: number, keepPolling?: (data: T) => boolean): Loadable<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(path !== null);
  const [tick, setTick] = useState(0);
  const latest = useRef(path);
  latest.current = path;

  useEffect(() => {
    if (path === null) {
      setData(null);
      setLoading(false);
      return;
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const load = (first: boolean) => {
      if (first) setLoading(true);
      get<T>(path)
        .then((value) => {
          if (cancelled || latest.current !== path) return;
          setData(value);
          setError(null);
          setLoading(false);
          if (pollMs && (!keepPolling || keepPolling(value))) timer = setTimeout(() => load(false), pollMs);
        })
        .catch((reason: Error) => {
          if (cancelled) return;
          setError(reason.message);
          setLoading(false);
        });
    };
    load(true);
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
    // keepPolling is intentionally excluded: callers pass inline predicates.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, tick, pollMs]);

  const reload = useCallback(() => setTick((value) => value + 1), []);
  return { data, error, loading, reload };
}

export function useLocalState<T>(key: string, initial: T): [T, (value: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = window.localStorage.getItem(key);
      return stored === null ? initial : (JSON.parse(stored) as T);
    } catch {
      return initial;
    }
  });
  const update = useCallback(
    (next: T) => {
      setValue(next);
      try {
        window.localStorage.setItem(key, JSON.stringify(next));
      } catch {
        /* storage unavailable: keep in memory only */
      }
    },
    [key],
  );
  return [value, update];
}
