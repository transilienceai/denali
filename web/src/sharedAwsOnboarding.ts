import type { SharedAwsConfiguration } from "./api";
import type { AwsSelectedResource } from "./types";

export const SHARED_AWS_SCOPES = [
  { id: "aws.bedrock_agents", label: "Bedrock agents and guardrails" },
  { id: "aws.agentcore", label: "AgentCore inventory" },
  { id: "aws.agent_runtime_activity", label: "AgentCore runtime activity" },
  { id: "aws.bedrock_activity", label: "Bedrock management activity" },
  { id: "aws.bedrock_logging", label: "Invocation logging configuration" },
  { id: "aws.code_to_cloud", label: "Code-to-cloud deployments" },
];

export type AwsAccessSelection = {
  coverageMode: "selected" | "automatic" | "selected-resource";
  selectedResource?: AwsSelectedResource;
  regionText: string;
  deploymentRegion: string;
  scopes: string[];
};

export const INITIAL_AWS_ACCESS: AwsAccessSelection = {
  coverageMode: "selected", regionText: "us-east-1", deploymentRegion: "us-east-1", scopes: ["aws.bedrock_agents"],
};

export function sharedAwsConfiguration(selection: AwsAccessSelection): SharedAwsConfiguration {
  if (selection.coverageMode === "selected-resource") {
    const pins = selection.selectedResource;
    const functionMatch = pins?.function_arn.match(/^arn:(aws|aws-us-gov|aws-cn):lambda:([a-z]{2}(?:-[a-z]+)+-[0-9]):([0-9]{12}):function:([A-Za-z0-9_-]{1,64})$/);
    const roleMatch = pins?.execution_role_arn.match(/^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role\/(?:[A-Za-z0-9_+=,.@-]+\/)*[A-Za-z0-9_+=,.@-]{1,64}$/);
    if (!pins || pins.kind !== "lambda_zip" || !functionMatch || !roleMatch ||
      functionMatch[1] !== roleMatch[1] || functionMatch[3] !== roleMatch[2] ||
      (functionMatch[1] === "aws-cn") !== functionMatch[2].startsWith("cn-") ||
      (functionMatch[1] === "aws-us-gov") !== functionMatch[2].startsWith("us-gov-") ||
      !pins.expected_model_id || pins.expected_model_id.length > 300 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(pins.expected_model_id)) {
      throw new Error("Provide an exact unqualified Zip Lambda ARN, its execution role ARN in the same account, and an expected Bedrock model identifier.");
    }
    return { coverage_mode: "selected-resource", regions: [functionMatch[2]], deployment_region: functionMatch[2], declared_scopes: ["aws.code_to_cloud"], selected_resource: { ...pins } };
  }
  const regions = selection.coverageMode === "automatic" ? [] : selection.regionText.split(/[\s,;]+/).filter(Boolean);
  const deployment = selection.deploymentRegion.trim();
  const regionPattern = /^[a-z]{2}(?:-[a-z]+)+-[0-9]+$/;
  if (!regionPattern.test(deployment) || regions.some((region) => !regionPattern.test(region)) ||
    new Set(regions).size !== regions.length || regions.length > 40 ||
    (selection.coverageMode === "selected" && (!regions.length || !regions.includes(deployment)))) {
    throw new Error("Select up to 40 unique AWS Regions and include the deployment Region, or use automatic coverage.");
  }
  if (!selection.scopes.length || new Set(selection.scopes).size !== selection.scopes.length ||
    selection.scopes.some((scope) => !SHARED_AWS_SCOPES.some((available) => available.id === scope))) {
    throw new Error("Select the AWS evidence to connect.");
  }
  return { coverage_mode: selection.coverageMode, regions, deployment_region: deployment, declared_scopes: [...selection.scopes].sort() };
}
