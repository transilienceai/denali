import type { Connection } from "./types";

export type ConnectionCollectionKind = "deployment" | "runtime" | "evidence" | "source";

export function selectedCollectionKinds(connection: Connection): ConnectionCollectionKind[] {
  if (connection.provider === "github" || connection.provider === "azure_repos") return ["source"];
  if (connection.provider === "entra" || connection.provider === "google_workspace") return ["evidence"];
  if (connection.provider !== "aws" && connection.provider !== "azure") return ["deployment"];
  const runtimeScope = `${connection.provider}.agent_runtime_activity`;
  const scopes = connection.declared_scopes ?? [];
  return [
    ...(scopes.some((scope) => scope !== runtimeScope) ? ["deployment" as const] : []),
    ...(scopes.includes(runtimeScope) ? ["runtime" as const] : []),
  ];
}

export function collectionResult(connection: Connection, kind: ConnectionCollectionKind) {
  return connection[`last_${kind}_collection`] ?? null;
}

function resultComplete(result: ReturnType<typeof collectionResult>) {
  return result?.state === "complete" && !("repository_count" in result
    && result.completed_repository_count !== undefined
    && result.completed_repository_count < result.repository_count);
}

export function connectionCollectionStatus(connection: Connection, kinds = selectedCollectionKinds(connection)) {
  const results = kinds.map((kind) => collectionResult(connection, kind));
  const running = kinds.some((kind) => connection[`${kind}_collection_state`] === "running");
  return {
    running,
    hasResults: results.some((result) => result !== null),
    complete: !running && kinds.length > 0 && results.every(resultComplete),
    attention: !running && results.some((result) => result && !resultComplete(result)),
  };
}

// A queued job may still expose the previous result. Missing or unchanged results
// are never proof that the operation just accepted by the API has finished.
export function collectionResultsChanged(
  previous: Connection,
  current: Connection,
  kinds: ConnectionCollectionKind[] = selectedCollectionKinds(previous),
) {
  return kinds.length > 0 && kinds.every((kind) => {
    const completedAt = collectionResult(current, kind)?.completed_at ?? null;
    return Boolean(completedAt) && completedAt !== (collectionResult(previous, kind)?.completed_at ?? null);
  });
}
