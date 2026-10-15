import assert from "node:assert/strict";
import test from "node:test";
import { collectionResultsChanged, connectionCollectionStatus, selectedCollectionKinds } from "../src/connectionCollections.ts";
import { connectionJourney } from "../src/connectionOnboarding.ts";
import { getConnectionProgress } from "../src/connectionProgress.ts";
import { completedRunningConnectionIds, runningConnectionOperations } from "../src/connectionMonitoring.ts";
import { waitForAcceptedOperation } from "../src/connectionPolling.ts";
import type { Connection } from "../src/types.ts";

function connection(provider: "aws" | "azure", scopes: string[], overrides: Partial<Connection> = {}): Connection {
  return {
    id: "connection-runtime", provider, declared_scopes: scopes, health_state: "healthy", lifecycle_state: "active",
    credential_reference: { type: provider === "aws" ? "platform_shared_aws" : "platform_shared_azure", platform_connection_id: "shared-runtime" },
    validation_state: "idle", deployment_collection_state: "idle", runtime_collection_state: "idle",
    last_deployment_collection: null, last_runtime_collection: null, configuration: {}, ...overrides,
  } as Connection;
}
const runtimeResult = (state: "complete" | "partial" | "failed" = "complete", completed_at = "2026-10-16T00:01:00Z") => ({ state, completed_at });
const deploymentResult = (completed_at = "2026-10-16T00:01:00Z") => ({ state: "complete", completed_at }) as Connection["last_deployment_collection"];

for (const provider of ["aws", "azure"] as const) {
  const runtime = `${provider}.agent_runtime_activity`;
  const deployment = `${provider}.ai_services`;
  test(`${provider}: collection selection follows only declared evidence planes`, () => {
    assert.deepEqual(selectedCollectionKinds(connection(provider, [runtime])), ["runtime"]);
    assert.deepEqual(selectedCollectionKinds(connection(provider, [deployment])), ["deployment"]);
    assert.deepEqual(selectedCollectionKinds(connection(provider, [deployment, runtime])), ["deployment", "runtime"]);
    assert.deepEqual(selectedCollectionKinds(connection(provider, [])), []);
  });

  test(`${provider}: runtime-only work restores progress and dependent refresh after navigation`, () => {
    const running = connection(provider, [runtime], { runtime_collection_state: "running" });
    const done = { ...running, runtime_collection_state: "idle" as const, last_runtime_collection: runtimeResult() };
    assert.equal(getConnectionProgress(running, null)?.phase, "collecting");
    assert.equal(runningConnectionOperations([running]).length, 1);
    assert.deepEqual(completedRunningConnectionIds([running], [done]), [running.id]);
    assert.equal(connectionJourney(running)[2]?.state, "current");
    assert.equal(connectionJourney(done)[2]?.state, "complete");
    assert.equal(connectionCollectionStatus(done).complete, true);
    assert.equal(collectionResultsChanged(running, done), true);
  });

  test(`${provider}: old complete results cannot hide a queued/running rerun`, () => {
    const queued = connection(provider, [runtime], { runtime_collection_state: "running", last_runtime_collection: runtimeResult() });
    assert.equal(connectionCollectionStatus(queued).complete, false);
    assert.equal(connectionJourney(queued)[2]?.state, "current");
    assert.equal(collectionResultsChanged(queued, queued), false);
    assert.equal(collectionResultsChanged(queued, { ...queued, runtime_collection_state: "idle" }), false);
  });

  test(`${provider}: missing results and unchanged deployment results never prove completion`, () => {
    const previous = connection(provider, [runtime]);
    assert.equal(collectionResultsChanged(previous, previous), false);
    assert.equal(connectionCollectionStatus(previous).complete, false);
    assert.equal(collectionResultsChanged(previous, { ...previous, last_deployment_collection: deploymentResult() }), false);
    assert.equal(collectionResultsChanged(connection(provider, []), connection(provider, [])), false);
  });

  test(`${provider}: mixed evidence waits for both planes in either completion order`, async () => {
    const previous = connection(provider, [deployment, runtime]);
    const running = { ...previous, deployment_collection_state: "running" as const, runtime_collection_state: "running" as const };
    const done = { ...previous, last_deployment_collection: deploymentResult(), last_runtime_collection: runtimeResult() };
    for (const first of [
      { ...running, deployment_collection_state: "idle" as const, last_deployment_collection: deploymentResult() },
      { ...running, runtime_collection_state: "idle" as const, last_runtime_collection: runtimeResult() },
    ]) {
      assert.equal(collectionResultsChanged(previous, first), false);
      assert.equal(connectionCollectionStatus(first).complete, false);
      assert.equal(connectionJourney(first)[2]?.state, "current");
      const states = [first, done];
      let reads = 0;
      const result = await waitForAcceptedOperation({
        fetchCurrent: async () => { reads += 1; return states.shift()!; }, delay: async () => {},
        isRunning: (row) => connectionCollectionStatus(row).running,
        isComplete: (row) => collectionResultsChanged(previous, row),
        stoppedMessage: "stopped", timeoutMessage: "timeout",
      });
      assert.equal(reads, 2);
      assert.equal(result, done);
    }
  });

  test(`${provider}: mixed missing or failed runtime is not Ready despite successful deployments`, () => {
    const previous = connection(provider, [deployment, runtime]);
    const deploymentOnly = { ...previous, last_deployment_collection: deploymentResult() };
    assert.equal(connectionCollectionStatus(deploymentOnly).complete, false);
    assert.equal(collectionResultsChanged(previous, deploymentOnly), false);
    for (const state of ["partial", "failed"] as const) {
      const failed = { ...deploymentOnly, last_runtime_collection: runtimeResult(state) };
      assert.equal(collectionResultsChanged(previous, failed), true); // terminal result, not success
      assert.equal(connectionCollectionStatus(failed).complete, false);
      assert.equal(connectionCollectionStatus(failed).attention, true);
      assert.equal(connectionJourney(failed)[2]?.state, "attention");
    }
  });
}

test("runtime-only collection without a result cannot return a false success", async () => {
  const previous = connection("azure", ["azure.agent_runtime_activity"]);
  await assert.rejects(waitForAcceptedOperation({
    fetchCurrent: async () => previous, delay: async () => {},
    isRunning: (row) => connectionCollectionStatus(row).running,
    isComplete: (row) => collectionResultsChanged(previous, row),
    stoppedMessage: "selected plane stopped without a result", timeoutMessage: "timeout",
  }), /selected plane stopped without a result/);
});
