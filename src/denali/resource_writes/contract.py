"""Product-owned versioned named write surface; adapters pin this source."""

RESOURCE_WRITE_CONTRACT_VERSION = 1
RESOURCE_WRITE_RECEIVER = "/internal/v1/capabilities/resource-writes/actions"
RESOURCE_WRITE_PURPOSES = {
    "github.guardrail_draft_pr": "denali:github-remediation:write",
    "aws.tighten_bedrock_inline_policy": "denali:aws-remediation:write",
}
