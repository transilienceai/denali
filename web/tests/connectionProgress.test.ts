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
  assert.equal(progress?.title, "Verifying the AWS role and declared access");
  assert.match(progress?.detail ?? "", /retries every 10 seconds for up to 15 minutes/);
  assert.match(progress?.detail ?? "", /review the stack Events/);
  assert.deepEqual(progress?.steps.map((step) => step.state), ["current", "pending", "pending"]);
});

test("restores the AWS onboarding wait from durable state after navigation", () => {
  const progress = getConnectionProgress(connection({
    provider: "aws",
    validation_state: "running",
    credential_reference: { type: "aws_assume_role", role_arn: "arn:aws:iam::123456789012:role/Denali" },
  }), null);

  assert.equal(progress?.title, "Verifying the AWS role and declared access");
  assert.deepEqual(progress?.steps.map((step) => step.label), ["Check IAM role access", "Validate access", "Collect evidence"]);
});

test("an AWS retry with a previous credential failure never claims setup is complete", () => {
  const previous = {
    started_at: "2026-10-19T00:00:00Z", completed_at: "2026-10-19T00:15:00Z",
    credential_state: "failed" as const, health_state: "unhealthy" as const,
    account_id_observed: null, summary: "Previous AccessDenied", results: [],
  };
  for (const busy of [null, "launch:connection-1", "validate:connection-1"]) {
    const progress = getConnectionProgress(connection({
      provider: "aws", validation_state: busy ? "idle" : "running", last_validation: previous,
      credential_reference: { type: "aws_assume_role", role_arn: "arn:aws:iam::123456789012:role/SeparateReader" },
    }), busy);
    assert.equal(progress?.title, "Verifying the AWS role and declared access");
    assert.deepEqual(progress?.steps.map((step) => step.state), ["current", "pending", "pending"]);
    assert.match(progress?.detail ?? "", /CloudFormation launch normally retries/);
    assert.match(progress?.detail ?? "", /manual validation checks current access without waiting/);
    assert.match(progress?.detail ?? "", /Previous results remain historical/);
    assert.doesNotMatch(progress?.detail ?? "", /Previous AccessDenied/);
  }
});

test("a previous AWS credential pass is not proof of the active run's role access", () => {
  const progress = getConnectionProgress(connection({
    provider: "aws", validation_state: "running",
    credential_reference: { type: "aws_assume_role", role_arn: "arn:aws:iam::123456789012:role/SeparateReader" },
    last_validation: { started_at: "2026-10-19T00:00:00Z", completed_at: "2026-10-19T00:01:00Z", credential_state: "passed", health_state: "partial", account_id_observed: "123456789012", summary: "Previous partial plane coverage", results: [] },
  }), null);
  assert.equal(progress?.title, "Verifying the AWS role and declared access");
  assert.deepEqual(progress?.steps.map((step) => step.state), ["current", "pending", "pending"]);
  assert.deepEqual(progress?.steps.map((step) => step.label), ["Check IAM role access", "Validate access", "Collect evidence"]);
  assert.match(progress?.detail ?? "", /Previous results remain historical/);
  assert.ok(progress?.steps.every((step) => step.state !== "complete"));
});
