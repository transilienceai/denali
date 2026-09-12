import assert from "node:assert/strict";
import test from "node:test";

import {
  completedRunningConnectionIds,
  markConnectionOperationRunning,
  runningConnectionOperations,
} from "../src/connectionMonitoring.ts";
import type { Connection } from "../src/types.ts";

function connection(overrides: Partial<Connection> = {}): Connection {
  return {
    id: "connection-1",
    provider: "gcp",
    display_name: "Production Google Cloud",
    lifecycle_state: "active",
    health_state: "unknown",
    validation_state: "idle",
    deployment_collection_state: "idle",
    setup_capabilities: {
      cloudformation_quick_create: false,
      azure_cloud_shell: false,
      gcp_cloud_shell: true,
      github_app: false,
      entra_admin_consent: false,
      google_workspace_admin_authorization: false,
    },
    credential_reference: {
      type: "gcp_service_account",
      principal_email: "denali@example.iam.gserviceaccount.com",
    },
    declared_scopes: [],
    coverage_plan: [],
    configuration: {},
    created_at: "2026-09-09T00:00:00Z",
    updated_at: "2026-09-09T00:00:00Z",
    last_validated_at: null,
    last_validation: null,
    ...overrides,
  };
}

test("hands an accepted validation operation to the app-level monitor immediately", () => {
  const original = connection();
  const updated = markConnectionOperationRunning([original], original.id, "validation");

  assert.equal(original.validation_state, "idle");
  assert.equal(updated[0]?.validation_state, "running");
  assert.equal(runningConnectionOperations(updated)[0]?.progress.title, "Google Cloud access is being validated");
});

test("marks each collection kind on its matching durable state field", () => {
  assert.equal(markConnectionOperationRunning([connection()], "connection-1", "deployment")[0]?.deployment_collection_state, "running");
  assert.equal(markConnectionOperationRunning([connection()], "connection-1", "runtime")[0]?.runtime_collection_state, "running");
  assert.equal(markConnectionOperationRunning([connection()], "connection-1", "evidence")[0]?.evidence_collection_state, "running");
  assert.equal(markConnectionOperationRunning([connection()], "connection-1", "source")[0]?.source_collection_state, "running");
});

test("detects a durable operation transition so dependent data can be refreshed", () => {
  const previous = [connection({ validation_state: "running" })];
  const current = [connection({ validation_state: "idle", health_state: "healthy" })];

  assert.deepEqual(completedRunningConnectionIds(previous, current), ["connection-1"]);
  assert.deepEqual(completedRunningConnectionIds(previous, previous), []);
});
