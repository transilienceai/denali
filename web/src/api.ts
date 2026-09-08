import type {
  Asset,
  AssetDetail,
  AwsConnectionCreate,
  AwsCloudFormationLaunch,
  AzureConnectionCreate,
  AzureSetupLaunch,
  EntraConnectionCreate,
  EntraSetupLaunch,
  GcpConnectionCreate,
  GcpSetupLaunch,
  GitHubConnectionCreate,
  GitHubSetupLaunch,
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
  RuntimeDetection,
  RuntimeDetectionDetail,
  RuntimeDetectionEvaluation,
  RuntimeDetectionSummary,
  Summary,
  Vulnerability,
  VulnerabilityDetail,
  VulnerabilitySummary,
} from "./types";

const API_BASE = "/api";

export type DenaliContext = {
  tenant_id: string;
  organization_id: string | null;
  role: "admin" | "member";
  can_write: boolean;
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

type TokenProvider = () => Promise<string | null>;
let tokenProvider: TokenProvider = async () => null;

export function configureApiTokenProvider(provider: TokenProvider) {
  tokenProvider = provider;
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
      if (typeof payload.detail === "string") throw new Error(payload.detail);
    }
    throw new Error(`Request failed (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

async function requestBlob(path: string): Promise<Blob> {
  const token = await tokenProvider();
  const response = await fetch(`${API_BASE}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.blob();
}

export const api = {
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
  connection: (id: string) => request<Connection>(`/v1/connections/${id}`),
  createConnection: (connection: AwsConnectionCreate | AzureConnectionCreate | EntraConnectionCreate | GcpConnectionCreate | GitHubConnectionCreate) =>
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
  collectGitHubSource: (id: string) =>
    request<{ status: "started" | "already_running"; connection_id: string }>(
      `/v1/connections/${id}/github/collect`,
      { method: "POST" },
    ),
  summary: () => request<Summary>("/v1/inventory/summary"),
  assets: () => request<{ items: Asset[] }>("/v1/inventory/assets?limit=500"),
  asset: (id: string) => request<AssetDetail>(`/v1/inventory/assets/${id}`),
  coverage: () => request<{ items: Coverage[] }>("/v1/sources/coverage"),
  findingSummary: () => request<FindingSummary>("/v1/findings/summary"),
  findings: () => request<{ items: Finding[] }>("/v1/findings?limit=500"),
  finding: (id: string) => request<FindingDetail>(`/v1/findings/${id}`),
  vulnerabilitySummary: () => request<VulnerabilitySummary>("/v1/vulnerabilities/summary"),
  vulnerabilities: () => request<{ items: Vulnerability[] }>("/v1/vulnerabilities?limit=500"),
  vulnerability: (id: string) =>
    request<VulnerabilityDetail>(`/v1/vulnerabilities/${id}`),
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
  detectionSummary: () => request<RuntimeDetectionSummary>("/v1/detections/summary"),
  detections: () => request<{ items: RuntimeDetection[] }>("/v1/detections?limit=500"),
  detectionEvaluations: () =>
    request<{ items: RuntimeDetectionEvaluation[] }>("/v1/detections/evaluations"),
  detection: (id: string) =>
    request<RuntimeDetectionDetail>(`/v1/detections/${id}`),
  governance: (
    id: string,
    update: { status: Asset["governance_status"]; owner?: string | null; notes?: string | null },
  ) =>
    request<{ id: string; governance_status: string; owner: string | null; notes: string | null }>(
      `/v1/inventory/assets/${id}/governance`,
      { method: "PATCH", body: JSON.stringify(update) },
    ),
};
