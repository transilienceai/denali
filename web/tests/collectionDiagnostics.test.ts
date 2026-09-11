import assert from "node:assert/strict";
import test from "node:test";
import {
  collectionDiagnostic,
  noDeploymentExplanation,
} from "../src/collectionDiagnostics.ts";

test("collection error codes become actionable without hiding unknown detail", () => {
  assert.match(collectionDiagnostic("github_rate_limited") ?? "", /run collection again/i);
  assert.match(
    collectionDiagnostic("repository analysis budget selected 2 of 5 eligible files") ?? "",
    /missing evidence was not withdrawn/i,
  );
  assert.equal(collectionDiagnostic("custom safe detail"), "custom safe detail");
});

test("deployment empty states distinguish absent cloud evidence from absent source", () => {
  assert.match(noDeploymentExplanation(3, false), /no independent cloud inventory/i);
  assert.match(noDeploymentExplanation(3, true), /none matched/i);
  assert.match(noDeploymentExplanation(0, false), /no safely resolvable/i);
});
