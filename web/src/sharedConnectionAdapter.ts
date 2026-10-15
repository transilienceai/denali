import type { Connection } from "./types";

export type SharedConnectionAdapterProps = {
  canWrite: boolean;
  onChanged: () => Promise<void>;
  connection?: Connection;
  onAttached?: (connection: Connection) => void | Promise<void>;
  onProgress?: (phase: "grant" | "verify" | "collect", message?: string) => void;
};

export function platformConnectionId(connection?: Connection): string {
  const reference = connection?.credential_reference;
  return reference && "platform_connection_id" in reference
    ? String(reference.platform_connection_id) : "";
}

/** One request at a time; results from an abandoned selection are never applied. */
export function createSharedStatusReader<T>(
  request: () => Promise<T>,
  accept: (result: T) => void,
  reject: (error: unknown) => void,
) {
  let stopped = false;
  let pending: Promise<void> | null = null;
  return {
    refresh(): Promise<void> {
      if (stopped) return Promise.resolve();
      if (pending) return pending;
      pending = Promise.resolve().then(request).then(
        (result) => { if (!stopped) accept(result); },
        (error: unknown) => { if (!stopped) reject(error); },
      ).finally(() => { pending = null; });
      return pending;
    },
    stop() { stopped = true; },
  };
}
