import { getConnectionProgress, type ConnectionProgress } from "./connectionProgress.ts";
import type { Connection } from "./types";

export type ConnectionOperationKind = "validation" | "deployment" | "evidence" | "source" | "runtime";

export type RunningConnectionOperation = {
  connection: Connection;
  progress: ConnectionProgress;
};

const OPERATION_STATE_FIELDS: Record<ConnectionOperationKind, keyof Connection> = {
  validation: "validation_state",
  deployment: "deployment_collection_state",
  evidence: "evidence_collection_state",
  source: "source_collection_state",
  runtime: "runtime_collection_state",
};

export function markConnectionOperationRunning(
  connections: Connection[],
  connectionId: string,
  kind: ConnectionOperationKind,
) {
  const stateField = OPERATION_STATE_FIELDS[kind];
  return connections.map((connection) => connection.id === connectionId
    ? { ...connection, [stateField]: "running" }
    : connection);
}

export function runningConnectionOperations(connections: Connection[]): RunningConnectionOperation[] {
  return connections.flatMap((connection) => {
    const progress = getConnectionProgress(connection, null);
    return progress ? [{ connection, progress }] : [];
  });
}

export function completedRunningConnectionIds(previous: Connection[], current: Connection[]) {
  const currentById = new Map(current.map((connection) => [connection.id, connection]));
  return runningConnectionOperations(previous)
    .filter(({ connection }) => {
      const currentConnection = currentById.get(connection.id);
      return !currentConnection || getConnectionProgress(currentConnection, null) === null;
    })
    .map(({ connection }) => connection.id);
}
