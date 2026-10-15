import assert from "node:assert/strict";
import test from "node:test";
import { INITIAL_AWS_ACCESS, SHARED_AWS_SCOPES, sharedAwsConfiguration } from "../src/sharedAwsOnboarding.ts";

test("AWS defaults preserve the existing one-Region Bedrock selection", () => {
  assert.deepEqual(sharedAwsConfiguration(INITIAL_AWS_ACCESS), {
    coverage_mode: "selected", regions: ["us-east-1"], deployment_region: "us-east-1", declared_scopes: ["aws.bedrock_agents"],
  });
});

test("an explicit AWS selection can cover all six evidence planes and several Regions", () => {
  const result = sharedAwsConfiguration({ ...INITIAL_AWS_ACCESS, regionText: "us-east-1,eu-west-1", scopes: SHARED_AWS_SCOPES.map((scope) => scope.id) });
  assert.deepEqual(result.regions, ["us-east-1", "eu-west-1"]);
  assert.equal(result.declared_scopes.length, 6);
  const automatic = sharedAwsConfiguration({ ...INITIAL_AWS_ACCESS, coverageMode: "automatic", regionText: "" });
  assert.deepEqual(automatic.regions, []);
  assert.deepEqual(automatic.declared_scopes, ["aws.bedrock_agents"]);
});

test("AWS coverage rejects duplicate, unbounded, malformed, empty and undeclared selections", () => {
  for (const patch of [{ regionText: "" }, { regionText: "*" }, { regionText: "us-east-1,us-east-1" },
    { deploymentRegion: "eu-west-1" }, { scopes: [] }, { scopes: ["aws.cspm"] },
    { scopes: ["aws.bedrock_agents", "aws.bedrock_agents"] },
    { regionText: Array.from({ length: 41 }, (_, index) => `us-east-${index + 1}`).join(",") }]) {
    assert.throws(() => sharedAwsConfiguration({ ...INITIAL_AWS_ACCESS, ...patch }));
  }
});

test("exact Lambda coverage never inherits broad scopes or Regions", () => {
  const selectedResource = { kind: "lambda_zip" as const, function_arn: "arn:aws:lambda:eu-west-1:123456789012:function:fixture", execution_role_arn: "arn:aws:iam::123456789012:role/fixture-execution", expected_model_id: "amazon.nova-pro-v1:0" };
  const selection = { ...INITIAL_AWS_ACCESS, coverageMode: "selected-resource" as const, selectedResource, scopes: SHARED_AWS_SCOPES.map((scope) => scope.id), regionText: "us-west-2" };
  assert.deepEqual(sharedAwsConfiguration(selection), { coverage_mode: "selected-resource", selected_resource: selectedResource, regions: ["eu-west-1"], deployment_region: "eu-west-1", declared_scopes: ["aws.code_to_cloud"] });
  for (const patch of [{ function_arn: `${selectedResource.function_arn}:live` }, { execution_role_arn: "arn:aws:iam::999999999999:role/other" }, { expected_model_id: "" }, { function_arn: "arn:aws-cn:lambda:eu-west-1:123456789012:function:fixture" }]) {
    assert.throws(() => sharedAwsConfiguration({ ...selection, selectedResource: { ...selectedResource, ...patch } }));
  }
});
