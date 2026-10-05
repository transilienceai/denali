import assert from "node:assert/strict";
import test from "node:test";

import { sharedAwsFailureState, showNativeConnectionForm } from "../src/connectionOnboarding.ts";

test("only a dark bridge or a non-pilot organization keeps native AWS as the default", () => {
  assert.equal(sharedAwsFailureState(Object.assign(new Error("not allowed"), { status: 404 })), "not_enabled");
  assert.equal(sharedAwsFailureState(Object.assign(new Error("not configured"), { status: 503 })), "not_enabled");
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
