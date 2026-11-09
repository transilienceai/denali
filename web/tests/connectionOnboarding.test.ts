import assert from "node:assert/strict";
import test from "node:test";

import { connectionJourney, sharedAwsFailureState, showNativeConnectionForm } from "../src/connectionOnboarding.ts";
import type { Connection } from "../src/types.ts";

test("only an explicitly non-pilot organization is classified as not enabled", () => {
  assert.equal(sharedAwsFailureState(Object.assign(new Error("not allowed"), { status: 404 })), "not_enabled");
  assert.equal(sharedAwsFailureState(Object.assign(new Error("service unavailable"), { status: 503 })), "error");
  assert.equal(showNativeConnectionForm("aws", true, "not_enabled", false), true);
});

test("a configured but failing shared service never silently opens native AWS", () => {
  assert.equal(sharedAwsFailureState(Object.assign(new Error("upstream failed"), { status: 502 })), "error");
  assert.equal(sharedAwsFailureState(Object.assign(new Error("not authorized"), { status: 401 })), "error");
  assert.equal(sharedAwsFailureState(new Error("network failed")), "error");
  assert.equal(showNativeConnectionForm("aws", true, "checking", false), false);
  assert.equal(showNativeConnectionForm("aws", true, "enabled", false), false);
  assert.equal(showNativeConnectionForm("aws", true, "error", false), false);
  assert.equal(showNativeConnectionForm("aws", true, "error", true), true);
});

test("non-AWS provider links and the explicit legacy choice remain available", () => {
  assert.equal(showNativeConnectionForm("azure", true, "enabled", false), true);
  assert.equal(showNativeConnectionForm("gcp", true, "error", false), true);
  assert.equal(showNativeConnectionForm("aws", true, "enabled", true), true);
  assert.equal(showNativeConnectionForm("aws", false, "not_enabled", true), false);
});

test("every provider keeps Verify current during a rerun despite historical healthy access", () => {
  for (const provider of ["aws", "azure", "entra", "gcp", "github", "google_workspace", "azure_repos"] as const) {
    const kind = provider === "github" || provider === "azure_repos" ? "source" : provider === "entra" || provider === "google_workspace" ? "evidence" : "deployment";
    const historicalValidation = { credential_state: "passed", health_state: "healthy", completed_at: "2026-10-19T00:01:00Z", summary: "Previous healthy access", results: [] };
    const historicalCollection = { state: "complete", completed_at: "2026-10-19T00:02:00Z" };
    const connection = {
      provider, health_state: "healthy", validation_state: "running", declared_scopes: [`${provider}.metadata`], configuration: {},
      credential_reference: { type: `platform_shared_${provider}` }, last_validation: historicalValidation,
      [`last_${kind}_collection`]: historicalCollection,
    } as Connection;
    const before = structuredClone(connection);
    assert.deepEqual(connectionJourney(connection).map((step) => step.state), ["complete", "current", "complete"], provider);
    assert.equal(connectionJourney({ ...connection, validation_state: "idle" })[1].state, "complete", provider);
    assert.deepEqual(connection, before, "Journey presentation must not erase historical evidence");
    assert.equal(connection.last_validation, historicalValidation);
    assert.equal(connection[`last_${kind}_collection`], historicalCollection);
  }
});

test("prior exact-resource read proofs cannot complete Verify during active validation", () => {
  const historicalValidation = {
    credential_state: "passed", health_state: "partial", completed_at: "2026-10-19T00:01:00Z", summary: "Previously verified exact boundary",
    results: [{ state: "passed", plane: "selected_lambda" }, { state: "passed", plane: "selected_execution_role" }],
  };
  const historicalCollection = { state: "complete", completed_at: "2026-10-19T00:02:00Z", resource_coverage_state: "complete", account_coverage: "not_assessed" };
  const connection = {
    provider: "aws", health_state: "partial", validation_state: "running", declared_scopes: ["aws.code_to_cloud"],
    credential_reference: { type: "aws_assume_role" }, configuration: { coverage_mode: "selected-resource" },
    actions: { collect: true }, last_validation: historicalValidation, last_deployment_collection: historicalCollection,
  } as Connection;
  const before = structuredClone(connection);
  assert.deepEqual(connectionJourney(connection).map((step) => step.state), ["complete", "current", "complete"]);
  assert.equal(connectionJourney({ ...connection, validation_state: "idle" })[1].state, "complete");
  assert.deepEqual(connection, before);
  assert.equal(connection.last_validation, historicalValidation);
  assert.equal(connection.last_deployment_collection, historicalCollection);
});
