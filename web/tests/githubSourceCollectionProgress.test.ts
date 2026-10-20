import assert from "node:assert/strict";
import test from "node:test";
import { githubSourceCollectionCounts, githubSourceCollectionProgress } from "../src/githubSourceCollectionProgress.ts";
import { connectionCollectionStatus, collectionResultsChanged } from "../src/connectionCollections.ts";
import { getConnectionProgress } from "../src/connectionProgress.ts";
import { connectionJourney } from "../src/connectionOnboarding.ts";
import { completedRunningConnectionIds } from "../src/connectionMonitoring.ts";
import type { Connection, GitHubSourceCollectionProgress } from "../src/types.ts";

const progress: GitHubSourceCollectionProgress = {
  state: "running", repository_count: 113, completed_repository_count: 20,
  failed_count: 1, partial_count: 2, repositories: [], resume_pending: true,
  retry_after_seconds: 0, updated_at: "2026-10-20T00:01:00Z",
};
const previousResult = {
  connection_id: "github-source", state: "complete" as const, repository_count: 113,
  failed_count: 0, partial_count: 0, repositories: [], completed_at: "2026-10-19T00:01:00Z",
};
function connection(overrides: Partial<Connection> = {}): Connection {
  return {
    id: "github-source", provider: "github", lifecycle_state: "active", health_state: "healthy",
    source_collection_state: "running", last_source_collection: previousResult,
    source_collection_progress: progress, credential_reference: { type: "github_app_installation", installation_id: 1 },
    configuration: { repositories: Array.from({ length: 113 }, (_, id) => ({ id })) }, ...overrides,
  } as Connection;
}

test("GitHub active aggregates count processed outcomes without claiming complete coverage", () => {
  const row = connection();
  const active = githubSourceCollectionProgress(row)!;
  assert.equal(active.summary, "20 of 113 repositories processed");
  assert.equal(active.remaining, 93);
  assert.equal(active.complete, 17);
  assert.equal(active.partial, 2);
  assert.equal(active.failed, 1);
  assert.match(active.detail, /93 repositories remain queued.*resumable batches/);
  assert.equal(connectionCollectionStatus(row).running, true);
  assert.equal(connectionCollectionStatus(row).complete, false);
  assert.equal(connectionCollectionStatus(row).attention, false);
  assert.equal(connectionJourney(row)[2]!.state, "current");
  assert.equal(collectionResultsChanged(row, row), false);
});

test("GitHub provider cooldown remains running and resumes without a second collect", () => {
  const waiting = connection({ source_collection_progress: { ...progress, retry_after_seconds: 125 } });
  const active = githubSourceCollectionProgress(waiting)!;
  assert.equal(active.waiting, true);
  assert.equal(active.title, "Waiting for GitHub quota");
  assert.match(active.detail, /93 repositories remain queued.*3 minutes.*resumes automatically.*do not start another collection/);
  assert.equal(getConnectionProgress(waiting, null)?.title, "Waiting for GitHub quota");
  assert.match(getConnectionProgress(waiting, null)?.detail ?? "", /20 of 113 repositories processed/);
  assert.equal(connectionJourney(waiting)[2]!.state, "current");
  assert.deepEqual(completedRunningConnectionIds([waiting], [connection()]), []);
});

test("GitHub reload before the first checkpoint uses saved selection, never previous run counts", () => {
  const row = connection({ source_collection_progress: null });
  assert.equal(githubSourceCollectionProgress(row)?.summary, "0 of 113 repositories processed");
  assert.equal(githubSourceCollectionProgress(row)?.complete, 0);
  assert.match(getConnectionProgress(row, null)?.detail ?? "", /113 repositories remain queued/);
});

test("GitHub all processed still waits for the final terminal result", () => {
  const row = connection({ source_collection_progress: { ...progress, completed_repository_count: 113 } });
  assert.equal(githubSourceCollectionProgress(row)?.title, "Finalizing GitHub source collection");
  assert.match(githubSourceCollectionProgress(row)?.detail ?? "", /not complete yet/);
  assert.equal(connectionCollectionStatus(row).complete, false);
  assert.equal(collectionResultsChanged(connection(), row), false);
});

for (const state of ["complete", "partial", "failed"] as const) {
  test(`GitHub terminal ${state} remains distinct from job progress and access health`, () => {
    const running = connection();
    const done = connection({ source_collection_state: "idle", last_source_collection: { ...previousResult, state, completed_at: "2026-10-20T00:02:00Z" } });
    assert.equal(githubSourceCollectionProgress(done), null); // ignore stale progress defensively
    assert.equal(getConnectionProgress(done, null), null);
    assert.equal(collectionResultsChanged(running, done), true);
    assert.equal(connectionCollectionStatus(done).complete, state === "complete");
    assert.equal(connectionCollectionStatus(done).attention, state !== "complete");
    assert.equal(done.health_state, "healthy");
    assert.deepEqual(completedRunningConnectionIds([running], [done]), [done.id]);
  });
}

test("source progress is GitHub-only and safe counts never become negative", () => {
  assert.equal(githubSourceCollectionProgress(connection({ provider: "azure_repos" })), null);
  const active = githubSourceCollectionProgress(connection({ source_collection_progress: { ...progress, completed_repository_count: 200, failed_count: 150, partial_count: 150 } }))!;
  assert.equal(active.processed, 113);
  assert.equal(active.remaining, 0);
  assert.equal(active.complete, 0);
});

test("a terminal interrupted run counts only processed repositories, preserving legacy results", () => {
  const result = { ...previousResult, state: "failed" as const, completed_repository_count: 20, failed_count: 1, partial_count: 2 };
  assert.deepEqual(githubSourceCollectionCounts(result), { total: 113, processed: 20, complete: 17, partial: 2, failed: 1, remaining: 93 });
  assert.equal(githubSourceCollectionCounts(previousResult).complete, 113);
  const interrupted = connection({ source_collection_state: "idle", last_source_collection: result });
  assert.equal(connectionCollectionStatus(interrupted).complete, false);
  assert.equal(connectionJourney(interrupted)[2]!.state, "attention");
  assert.equal(connectionCollectionStatus({ ...interrupted, last_source_collection: { ...result, state: "complete" } }).complete, false);
});
