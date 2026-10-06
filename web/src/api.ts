import type {
  Asset,
  AssetDetail,
  AssetPage,
  AwsConnectionCreate,
  AwsCloudFormationLaunch,
  AzureConnectionCreate,
  AzureReposConnectionCreate,
  AzureReposSetupLaunch,
  AzureSetupLaunch,
  EntraConnectionCreate,
  EntraSetupLaunch,
  GcpConnectionCreate,
  GcpSetupLaunch,
  GitHubConnectionCreate,
  GitHubSetupLaunch,
  GoogleWorkspaceConnectionCreate,
  Connection,
  Coverage,
  CodeToCloudDeployment,
  CodeToCloudObservation,
  Finding,
  FindingDetail,
  FindingSummary,
  Issue,
  IssueDetail,
  IssueEvaluation,
  IssueSummary,
  RuntimeActivity,
  RuntimeActivityDetail,
  RuntimeActivitySummary,
  RuntimeSessionDetail,
  RuntimeSessionSummary,
  RuntimeDetection,
  RuntimeDetectionDetail,
  RuntimeDetectionEvaluation,
  RuntimeDetectionSummary,
  RuntimeResponseRequest,
  Summary,
  Vulnerability,
  VulnerabilityDetail,
  VulnerabilityImportJob,
  VulnerabilitySummary,
} from "./types";

const API_BASE = "/api";

export type DenaliContext = {
  tenant_id: string;
  organization_id: string | null;
  role: "admin" | "member";
  can_write: boolean;
};

export type ConnectionJobStatus = {
  job_id: string;
  connection_id: string;
  job_type: "validation" | "collection";
  collection_kind: string | null;
  state: "queued" | "running" | "succeeded" | "failed";
  attempt_count: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_code: "job_failed" | null;
};

export type OrganizationRole = "org:member" | "org:admin";

export type BulkInviteResult = {
  sent: number;
  failed: number;
  results: Array<{
    email: string;
    status: "sent" | "failed";
    invitation_id?: string;
    error?: string;
  }>;
};

export type CreatedOrganizationUser = {
  user_id: string;
  email: string;
  role: OrganizationRole;
};

export type SharedAwsConnection = {
  id: string;
  connection_kind: "shared_aws" | "legacy_metadata";
  provider: "aws";
  partition: string;
  external_account_id: string;
  availability: string;
  validated_scopes: string[];
  last_validated_at: string | null;
};

export type SharedAwsValidation = {
  job_state: string | null;
  health_state: string;
  credential_state: string;
  job_error_code: string | null;
  validation_summary: string | null;
};

export type SharedAwsProbe = {
  scope: "aws.bedrock_agents";
  region: string;
  read_state: "passed";
  sample_count: number;
};

export type SharedGitHubConnection = {
  id: string;
  connection_kind: "shared_github";
  provider: "github";
  account_id: number;
  account_login: string;
  installation_id: number;
  repository_selection: "all" | "selected";
  repository_count: number;
  availability: "ready" | "disabled" | "needs_scope_grant";
  validated_scopes: string[];
  last_validated_at?: string | null;
};

export type SharedGitHubRepository = {
  id: number; node_id: string; name: string; full_name: string;
  owner_id: number; owner_login: string; private: boolean; archived: boolean;
  default_branch: string | null;
};

export type SharedGcpConnection = {
  id: string;
  provider: "gcp";
  connection_kind: "shared_gcp";
  display_name: string;
  projects: Array<{ id: string; number: string }>;
  availability: string;
  validated_scopes: string[];
};

export type SharedGcpStatus = {
  job_state: string | null;
  setup_state: string;
  health_state: string;
  error_code: string | null;
  retry_available: boolean;
};

export type ResourceWriteAction = "github.guardrail_draft_pr" | "aws.tighten_bedrock_inline_policy";
export type ResourceWriteStatus = {
  id: string;
  preview_id: string;
  grant_id: string;
  action: ResourceWriteAction;
  state: "pending_review" | "approved" | "rejected" | "running" | "succeeded" | "failed" | "needs_manual_resolution";
  phase: "not_started" | "provider_attempted" | "finished";
  actor_user_id: string;
  reviewer_user_id: string | null;
  result: Record<string, unknown> | null;
  error_code: string | null;
};

type TokenProvider = () => Promise<string | null>;
let tokenProvider: TokenProvider = async () => null;

export function configureApiTokenProvider(provider: TokenProvider) {
  tokenProvider = provider;
}

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await tokenProvider();
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      const payload = await response.json() as { detail?: unknown };
      if (typeof payload.detail === "string") throw new ApiError(payload.detail, response.status);
    }
    throw new ApiError(`Request failed (${response.status})`, response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

async function requestBlob(path: string): Promise<Blob> {
  const token = await tokenProvider();
  const response = await fetch(`${API_BASE}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) throw new ApiError(`Request failed (${response.status})`, response.status);
  return response.blob();
}

export const api = {
  // Same product-owned service as MCP/CLI; no gateway/provider credentials in the browser.
  previewResourceWrite: (input: {
    finding_id: string; grant_id: string; expected_organization_id: string;
  } & ({ resource_action: "github.guardrail_draft_pr"; parameters: { guardrail_id: string; guardrail_version: string } }
     | { resource_action: "aws.tighten_bedrock_inline_policy"; parameters: { model_arns: string[] } })) =>
    request<{ preview_id: string; preview_sha256: string; plan: Record<string, unknown>; diff: string; expires_at: string; provider_mutated: false }>(
      "/v1/resource-writes/previews", { method: "POST", body: JSON.stringify(input) }),
  requestResourceWrite: (input: {
    preview_id: string; preview_sha256: string; justification: string;
    expected_organization_id: string; confirm: true;
  }, idempotencyKey: string) => request<ResourceWriteStatus>("/v1/resource-writes/requests", {
    method: "POST", headers: { "Idempotency-Key": idempotencyKey }, body: JSON.stringify(input),
  }),
  reviewResourceWrite: (id: string, input: {
    decision: "approved" | "rejected"; review_note: string; expected_organization_id: string; confirm: true;
  }) => request<ResourceWriteStatus>(`/v1/resource-writes/requests/${encodeURIComponent(id)}/review`, {
    method: "POST", body: JSON.stringify(input),
  }),
  resourceWriteStatus: (id: string) =>
    request<ResourceWriteStatus>(`/v1/resource-writes/requests/${encodeURIComponent(id)}`),
  reconcileResourceWrite: (id: string, expectedOrganizationId: string) =>
    request<ResourceWriteStatus>(`/v1/resource-writes/requests/${encodeURIComponent(id)}/reconcile`, {
      method: "POST", body: JSON.stringify({ expected_organization_id: expectedOrganizationId }),
    }),
  sharedGithubConnections: () => request<{ items: SharedGitHubConnection[] }>("/v1/shared/connections/github"),
  sharedGithubRepositories: (id: string) => request<{ items: SharedGitHubRepository[] }>(`/v1/shared/connections/github/${encodeURIComponent(id)}/repositories`),
  startSharedGithubSetup: () => request<{ install_url: string }>("/v1/shared/connections/github/setup", { method: "POST" }),
  useSharedGithubInDenali: (id: string) => request<Connection>(`/v1/shared/connections/github/${encodeURIComponent(id)}/use-in-denali`, { method: "POST", body: JSON.stringify({}) }),
  disableSharedGithub: (id: string) => request<{ status: string }>(`/v1/shared/connections/github/${encodeURIComponent(id)}/disable`, { method: "POST" }),
  sharedGcpConnections: () => request<{ items: SharedGcpConnection[] }>("/v1/shared/connections/gcp"),
  createSharedGcp: (input: { request_id: string; display_name: string; projects: Array<{ id: string; number: string }>; declared_scopes: string[] }) =>
    request<{ id: string; job_id: string; state: string }>("/v1/shared/connections/gcp", { method: "POST", body: JSON.stringify(input) }),
  sharedGcpStatus: (id: string) => request<SharedGcpStatus>(`/v1/shared/connections/gcp/${encodeURIComponent(id)}/validation`),
  sharedGcpScript: (id: string) => requestBlob(`/v1/shared/connections/gcp/${encodeURIComponent(id)}/setup.sh`),
  validateSharedGcp: (id: string) => request<{ job_id: string; state: string }>(`/v1/shared/connections/gcp/${encodeURIComponent(id)}/validate`, { method: "POST" }),
  useSharedGcp: (id: string, declaredScopes: string[]) => request<Connection>(`/v1/shared/connections/gcp/${encodeURIComponent(id)}/use-in-denali`, { method: "POST", body: JSON.stringify({ declared_scopes: declaredScopes }) }),
  disableSharedGcp: (id: string) => request<{ status: string }>(`/v1/shared/connections/gcp/${encodeURIComponent(id)}/disable`, { method: "POST" }),
  deleteSharedGcp: (id: string, confirmationName: string) => request<{ status: string }>(`/v1/shared/connections/gcp/${encodeURIComponent(id)}`, { method: "DELETE", body: JSON.stringify({ confirmation_name: confirmationName }) }),
  context: () => request<DenaliContext>("/v1/context"),
  inviteOrganizationMembers: (emails: string[], role: OrganizationRole) =>
    request<BulkInviteResult>("/v1/profile/organization/invitations/bulk", {
      method: "POST",
      body: JSON.stringify({ emails, role }),
    }),
  createOrganizationUser: (account: {
    email: string;
    password: string;
    first_name?: string;
    last_name?: string;
    role: OrganizationRole;
  }) =>
    request<CreatedOrganizationUser>("/v1/profile/organization/users", {
      method: "POST",
      body: JSON.stringify(account),
    }),
  connections: () => request<{ items: Connection[] }>("/v1/connections"),
  sharedAwsConnections: () => request<{ items: SharedAwsConnection[] }>("/v1/shared/connections"),
  createSharedAwsConnection: (accountId: string, region: string) =>
    request<{ id: string; availability: string }>("/v1/shared/connections/aws", {
      method: "POST",
      body: JSON.stringify({
        account_id: accountId,
        partition: "aws",
        deployment_region: region,
        coverage_mode: "selected",
        regions: [region],
        declared_scopes: ["aws.bedrock_agents"],
      }),
    }),
  sharedAwsTemplate: (id: string) =>
    requestBlob(`/v1/shared/connections/aws/${encodeURIComponent(id)}/cloudformation.yaml`),
  validateSharedAws: (id: string) =>
    request<{ job_id: string; state: string }>(
      `/v1/shared/connections/aws/${encodeURIComponent(id)}/validate`, { method: "POST" },
    ),
  sharedAwsValidation: (id: string) =>
    request<SharedAwsValidation>(
      `/v1/shared/connections/aws/${encodeURIComponent(id)}/validation`,
    ),
  probeSharedAws: (id: string, region: string) =>
    request<SharedAwsProbe>(`/v1/shared/connections/aws/${encodeURIComponent(id)}/probe`, {
      method: "POST",
      body: JSON.stringify({ region }),
    }),
  useSharedAwsInDenali: (id: string, region: string) =>
    request<Connection>(`/v1/shared/connections/aws/${encodeURIComponent(id)}/use-in-denali`, {
      method: "POST",
      body: JSON.stringify({ region, declared_scopes: ["aws.bedrock_agents"] }),
    }),
  disableSharedAws: (id: string) =>
    request<{ status: string }>(
      `/v1/shared/connections/aws/${encodeURIComponent(id)}/disable`, { method: "POST" },
    ),
  connection: (id: string) => request<Connection>(`/v1/connections/${id}`),
  connectionValidationJob: (connectionId: string, jobId: string) =>
    request<ConnectionJobStatus>(`/v1/connections/${connectionId}/validation-jobs/${jobId}`),
  connectionCollectionJob: (connectionId: string, jobId: string) =>
    request<ConnectionJobStatus>(`/v1/connections/${connectionId}/collection-jobs/${jobId}`),
  createConnection: (connection: AwsConnectionCreate | AzureConnectionCreate | AzureReposConnectionCreate | EntraConnectionCreate | GcpConnectionCreate | GitHubConnectionCreate | GoogleWorkspaceConnectionCreate) =>
    request<Connection>("/v1/connections", {
      method: "POST",
      body: JSON.stringify(connection),
    }),
  validateConnection: (id: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/validate`,
      { method: "POST" },
    ),
  disableConnection: (id: string) =>
    request<Connection>(`/v1/connections/${id}/disable`, { method: "POST" }),
  deleteConnection: (id: string, confirmation: string) =>
    request<void>(
      `/v1/connections/${id}?confirm=${encodeURIComponent(confirmation)}`,
      { method: "DELETE" },
    ),
  cloudFormationTemplate: (id: string) =>
    requestBlob(`/v1/connections/${id}/aws/cloudformation.yaml`),
  launchCloudFormation: (id: string) =>
    request<AwsCloudFormationLaunch>(
      `/v1/connections/${id}/aws/cloudformation/launch`,
      { method: "POST" },
    ),
  launchAzureSetup: (id: string) =>
    request<AzureSetupLaunch>(
      `/v1/connections/${id}/azure/setup/launch`,
      { method: "POST" },
    ),
  completeAzureSetup: (id: string, completionCode: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/azure/setup/complete`,
      { method: "POST", body: JSON.stringify({ completion_code: completionCode }) },
    ),
  launchEntraSetup: (id: string) =>
    request<EntraSetupLaunch>(
      `/v1/connections/${id}/entra/setup/launch`,
      { method: "POST" },
    ),
  collectEntraEvidence: (id: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/entra/collect`,
      { method: "POST" },
    ),
  completeGoogleWorkspaceSetup: (id: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/google-workspace/setup/complete`,
      { method: "POST" },
    ),
  collectGoogleWorkspaceEvidence: (id: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/google-workspace/collect`,
      { method: "POST" },
    ),
  launchGcpSetup: (id: string) =>
    request<GcpSetupLaunch>(
      `/v1/connections/${id}/gcp/setup/launch`,
      { method: "POST" },
    ),
  completeGcpSetup: (id: string, completionCode: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/gcp/setup/complete`,
      { method: "POST", body: JSON.stringify({ completion_code: completionCode }) },
    ),
  collectGcpDeployments: (id: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/gcp/collect-deployments`,
      { method: "POST" },
    ),
  collectAzureDeployments: (id: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/azure/collect-deployments`,
      { method: "POST" },
    ),
  collectAwsDeployments: (id: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/aws/collect-deployments`,
      { method: "POST" },
    ),
  launchGitHubSetup: (id: string) =>
    request<GitHubSetupLaunch>(
      `/v1/connections/${id}/github/setup/launch`,
      { method: "POST" },
    ),
  launchAzureReposSetup: (id: string) =>
    request<AzureReposSetupLaunch>(
      `/v1/connections/${id}/azure-repos/setup/launch`,
      { method: "POST" },
    ),
  completeAzureReposSetup: (id: string, repositoryIds: string[]) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/azure-repos/setup/complete`,
      { method: "POST", body: JSON.stringify({ repository_ids: repositoryIds }) },
    ),
  collectAzureReposSource: (id: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/azure-repos/collect`,
      { method: "POST" },
    ),
  collectGitHubSource: (id: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/github/collect`,
      { method: "POST" },
    ),
  summary: () => request<Summary>("/v1/inventory/summary"),
  assets: (filters: {
    category?: "all" | "ai" | "supporting" | "components";
    kind?: string;
    governance?: "all" | "approved" | "unreviewed" | "unwanted";
    q?: string;
    limit?: number;
    offset?: number;
  } = {}) => {
    const query = new URLSearchParams();
    query.set("category", filters.category ?? "all");
    query.set("limit", String(filters.limit ?? 100));
    query.set("offset", String(filters.offset ?? 0));
    if (filters.kind) query.set("kind", filters.kind);
    if (filters.governance && filters.governance !== "all") query.set("governance", filters.governance);
    if (filters.q?.trim()) query.set("q", filters.q.trim());
    return request<AssetPage>(`/v1/inventory/assets?${query.toString()}`);
  },
  asset: (id: string) => request<AssetDetail>(`/v1/inventory/assets/${id}`),
  coverage: () => request<{ items: Coverage[] }>("/v1/sources/coverage"),
  findingSummary: () => request<FindingSummary>("/v1/findings/summary"),
  findings: () => request<{ items: Finding[] }>("/v1/findings?limit=500"),
  finding: (id: string) => request<FindingDetail>(`/v1/findings/${id}`),
  vulnerabilitySummary: () => request<VulnerabilitySummary>("/v1/vulnerabilities/summary"),
  vulnerabilities: () => request<{ items: Vulnerability[] }>("/v1/vulnerabilities?limit=500"),
  vulnerability: (id: string) =>
    request<VulnerabilityDetail>(`/v1/vulnerabilities/${id}`),
  createVulnerabilityImport: (input: {
    target_asset_id: string;
    syft_report: Record<string, unknown>;
    grype_report: Record<string, unknown>;
    authoritative: boolean;
  }) => request<{ id: string; state: VulnerabilityImportJob["state"] }>(
    "/v1/vulnerabilities/imports",
    { method: "POST", body: JSON.stringify(input) },
  ),
  vulnerabilityImport: (id: string) =>
    request<VulnerabilityImportJob>(`/v1/vulnerabilities/imports/${id}`),
  issueSummary: () => request<IssueSummary>("/v1/issues/summary"),
  issues: () => request<{ items: Issue[] }>("/v1/issues?limit=500"),
  issue: (id: string) => request<IssueDetail>(`/v1/issues/${id}`),
  issueEvaluations: () => request<{ items: IssueEvaluation[] }>("/v1/issues/evaluations"),
  codeToCloudDeployments: () =>
    request<{ items: CodeToCloudDeployment[] }>("/v1/code-to-cloud/deployments"),
  codeToCloudObservations: () =>
    request<{ items: CodeToCloudObservation[] }>("/v1/code-to-cloud/observations"),
  activitySummary: (includeFixtures = false) =>
    request<RuntimeActivitySummary>(
      `/v1/activity/summary?include_fixtures=${includeFixtures}`,
    ),
  activity: (includeFixtures = false) =>
    request<{ items: RuntimeActivity[] }>(
      `/v1/activity?limit=500&include_fixtures=${includeFixtures}`,
    ),
  activityForAsset: (assetId: string) =>
    request<{ items: RuntimeActivity[] }>(
      `/v1/activity?asset_id=${encodeURIComponent(assetId)}&limit=500`,
    ),
  activityDetail: (id: string) =>
    request<RuntimeActivityDetail>(`/v1/activity/${id}`),
  runtimeSessions: () =>
    request<{ items: RuntimeSessionSummary[] }>(
      "/v1/runtime/sessions?limit=200",
    ),
  runtimeSession: (sessionKey: string) =>
    request<RuntimeSessionDetail>(
      `/v1/runtime/sessions/${encodeURIComponent(sessionKey)}`,
    ),
  runtimeSessionExport: (sessionKey: string) =>
    requestBlob(`/v1/runtime/sessions/${encodeURIComponent(sessionKey)}/export`),
  detectionSummary: () => request<RuntimeDetectionSummary>("/v1/detections/summary"),
  detections: () => request<{ items: RuntimeDetection[] }>("/v1/detections?limit=500"),
  detectionEvaluations: () =>
    request<{ items: RuntimeDetectionEvaluation[] }>("/v1/detections/evaluations"),
  detection: (id: string) =>
    request<RuntimeDetectionDetail>(`/v1/detections/${id}`),
  createRuntimeResponse: (
    detectionId: string,
    input: {
      action_type: RuntimeResponseRequest["action_type"];
      target_asset_id?: string | null;
      justification: string;
    },
  ) => request<RuntimeResponseRequest>(`/v1/detections/${detectionId}/responses`, {
    method: "POST",
    body: JSON.stringify(input),
  }),
  reviewRuntimeResponse: (
    detectionId: string,
    responseId: string,
    decision: "approved" | "rejected",
    reviewNote?: string,
  ) => request<RuntimeResponseRequest>(
    `/v1/detections/${detectionId}/responses/${responseId}`,
    { method: "PATCH", body: JSON.stringify({ decision, review_note: reviewNote }) },
  ),
  governance: (
    id: string,
    update: { status: Asset["governance_status"]; owner?: string | null; notes?: string | null },
  ) =>
    request<{ id: string; governance_status: string; owner: string | null; notes: string | null }>(
      `/v1/inventory/assets/${id}/governance`,
      { method: "PATCH", body: JSON.stringify(update) },
    ),
};
