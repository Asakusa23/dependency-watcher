import { useCallback, useEffect, useRef, useState } from "react";

interface ResourceState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

export function useApiResource<T>(
  loader: () => Promise<T>,
  key: string,
  options: { enabled?: boolean; pollWhile?: (data: T | null) => boolean; pollMs?: number } = {},
) {
  const { enabled = true, pollWhile, pollMs = 3000 } = options;
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const [state, setState] = useState<ResourceState<T>>({ data: null, loading: enabled, error: null });
  const [tick, setTick] = useState(0);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    if (!enabled) {
      setState((current) => ({ ...current, loading: false }));
      return;
    }
    let active = true;
    setState((current) => ({ ...current, loading: current.data == null, error: null }));
    loaderRef
      .current()
      .then((data) => {
        if (active && mounted.current) setState({ data, loading: false, error: null });
      })
      .catch((error: unknown) => {
        if (active && mounted.current) {
          setState((current) => ({
            data: current.data,
            loading: false,
            error: error instanceof Error ? error.message : "Request failed",
          }));
        }
      });
    return () => {
      active = false;
    };
  }, [enabled, key, tick]);

  useEffect(() => {
    if (!enabled || !pollWhile || !pollWhile(state.data)) return;
    const timer = window.setInterval(() => setTick((value) => value + 1), pollMs);
    return () => window.clearInterval(timer);
  }, [enabled, pollWhile, pollMs, state.data]);

  const reload = useCallback(() => setTick((value) => value + 1), []);
  return { ...state, reload };
}
