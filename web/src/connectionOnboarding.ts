import type { Connection } from "./types";

type ConnectionProvider = Connection["provider"];

export type SharedAwsAvailability = "checking" | "enabled" | "not_enabled" | "error";

export function sharedAwsFailureState(cause: unknown): SharedAwsAvailability {
  // 404 is the server-side organization allowlist; 503 means the bridge is dark.
  // Once configured, upstream failures must not silently create a native role.
  const status = cause instanceof Error && "status" in cause ? cause.status : null;
  return status === 404 || status === 503
    ? "not_enabled"
    : "error";
}

export function showNativeConnectionForm(
  provider: ConnectionProvider,
  showCreate: boolean,
  availability: SharedAwsAvailability,
  nativeRequested: boolean,
): boolean {
  if (!showCreate) return false;
  if (nativeRequested || provider !== "aws") return true;
  return availability === "not_enabled";
}
