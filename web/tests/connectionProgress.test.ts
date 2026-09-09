import assert from "node:assert/strict";
import test from "node:test";

import { getConnectionProgress } from "../src/connectionProgress.ts";
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

test("shows validation immediately after setup completion is submitted", () => {
  const progress = getConnectionProgress(connection(), "complete:connection-1");

  assert.equal(progress?.phase, "validating");
  assert.equal(progress?.title, "Google Cloud access is being validated");
  assert.match(progress?.detail ?? "", /automatically continues to first evidence collection/);
  assert.deepEqual(progress?.steps.map((step) => step.state), ["complete", "current", "pending"]);
});

test("keeps validation visible when the durable backend job is running", () => {
  const progress = getConnectionProgress(connection({ validation_state: "running" }), null);

  assert.equal(progress?.phase, "validating");
});

test("shows collection and preserves a partial validation warning", () => {
  const progress = getConnectionProgress(connection({
    health_state: "partial",
    deployment_collection_state: "running",
  }), null);

  assert.equal(progress?.phase, "collecting");
  assert.deepEqual(progress?.steps.map((step) => step.state), ["complete", "attention", "current"]);
});

test("shows setup preparation only for the selected connection", () => {
  assert.equal(getConnectionProgress(connection(), "launch:another-connection"), null);

  const progress = getConnectionProgress(connection(), "launch:connection-1");
  assert.equal(progress?.phase, "preparing");
});

test("treats AWS launch as the start of setup validation", () => {
  const progress = getConnectionProgress(connection({
    provider: "aws",
    credential_reference: { type: "aws_assume_role", role_arn: "arn:aws:iam::123456789012:role/Denali" },
  }), "launch:connection-1");

  assert.equal(progress?.phase, "validating");
  assert.equal(progress?.title, "AWS access is being validated");
});
