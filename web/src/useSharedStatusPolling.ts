import { useCallback, useEffect, useRef } from "react";
import { createSharedStatusReader } from "./sharedConnectionAdapter";

/** Durable status stays on the server; this hook owns only the visible selection. */
export function useSharedStatusPolling<T>({ identity, read, accept, reject, pending }: {
  identity: string | undefined;
  read: (id: string) => Promise<T>;
  accept: (result: T) => void;
  reject: (error: unknown) => void;
  pending: (result: T) => boolean;
}) {
  const callbacks = useRef({ read, accept, reject, pending });
  callbacks.current = { read, accept, reject, pending };
  const trigger = useRef<() => Promise<void>>(() => Promise.resolve());

  useEffect(() => {
    if (!identity) { trigger.current = () => Promise.resolve(); return; }
    let polling = false;
    const reader = createSharedStatusReader(
      () => callbacks.current.read(identity),
      (result) => {
        polling = callbacks.current.pending(result);
        callbacks.current.accept(result);
      },
      (error) => { callbacks.current.reject(error); },
    );
    trigger.current = reader.refresh;
    void reader.refresh();
    const timer = window.setInterval(() => {
      if (polling && document.visibilityState !== "hidden") void reader.refresh();
    }, 3000);
    const onReturn = () => { if (document.visibilityState !== "hidden") void reader.refresh(); };
    window.addEventListener("focus", onReturn);
    document.addEventListener("visibilitychange", onReturn);
    return () => {
      reader.stop();
      trigger.current = () => Promise.resolve();
      window.clearInterval(timer);
      window.removeEventListener("focus", onReturn);
      document.removeEventListener("visibilitychange", onReturn);
    };
  }, [identity]);

  return useCallback(() => trigger.current(), []);
}
