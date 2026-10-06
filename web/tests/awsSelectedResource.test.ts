import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const ui = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/types.ts", import.meta.url), "utf8");

test("native exact-resource form exposes all pins and only the code-to-cloud plane", () => {
  for (const field of ["function_arn", "execution_role_arn", "expected_model_id"]) {
    assert.ok(types.includes(`${field}: string`));
    assert.ok(ui.includes(field));
  }
  assert.match(types, /selected_resource\?: AwsSelectedResource/);
  assert.match(ui, /One exact Zip Lambda · partial account coverage/);
  assert.match(ui, /coverageMode === "selected-resource" \? \[deploymentRegion\]/);
  assert.match(ui, /declared_scopes: coverageMode === "selected-resource" \? \["aws.code_to_cloud"\]/);
  assert.match(ui, /provider === "aws" && coverageMode === "selected-resource"\)\}/);
  assert.match(ui, /Exact Zip Lambda ARN/);
  assert.match(ui, /Exact Lambda execution-role ARN/);
  assert.match(ui, /Approved expected Bedrock model ID or ARN/);
});

test("exact detail discloses partial coverage, no discovery and separate reader setup", () => {
  assert.match(ui, /Account-wide inventory and enabled Regions are not assessed/);
  assert.match(ui, /Do not delete or replace an existing discovery stack/);
  assert.match(ui, /exactResource \? \[\] : \["ec2:DescribeRegions"\]/);
  assert.match(ui, /Selected-resource coverage: \{collection.resource_coverage_state\}/);
  assert.match(ui, /Attached policies are only inventoried/);
  assert.match(ui, /Other environment values and arbitrary tags are not retained/);
});

test("omitted selection retains automatic legacy form and relative API routing", () => {
  assert.match(ui, /useState<AwsConnectionCreate\["coverage_mode"\]>\("automatic"\)/);
  assert.match(ui, /coverageMode === "selected-resource" \? \{ selected_resource:/);
  const api = readFileSync(new URL("../src/api.ts", import.meta.url), "utf8");
  assert.match(api, /const API_BASE = "\/api"/);
  assert.doesNotMatch(api, /selected_resource.*(modal\.run|amazonaws\.com)/);
});
