export type Asset = {
  id: string;
  kind: string;
  natural_key: string;
  governance_status: "approved" | "unreviewed" | "unwanted";
  lifecycle_state: string;
  owner: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_changed_at: string;
  display_name: string | null;
  attributes: Record<string, unknown> | null;
  assertion_type: string | null;
  confidence: number | null;
  connector_id: string | null;
  connection_id: string | null;
};

export type Evidence = {
  source_type: string;
  locator: string;
  observed_at: string;
  payload: Record<string, unknown>;
};

export type AssetAssertion = {
  connector_id: string;
  connection_id: string;
  scope_key: string;
  coverage_plane: string;
  assertion_type: string;
  confidence: number;
  display_name: string;
  attributes: Record<string, unknown>;
  evidence: Evidence;
  lifecycle_state: string;
  first_seen_at: string;
  last_seen_at: string;
  withdrawn_at: string | null;
};

export type Relationship = {
  id: string;
  kind: string;
  category: string;
  assertion_type: string;
  confidence: number;
  attributes: Record<string, unknown>;
  evidence: Evidence;
  withdrawn_at: string | null;
  source_id: string;
  source_kind: string;
  source_natural_key: string;
  target_id: string;
  target_kind: string;
  target_natural_key: string;
};

export type AssetDetail = Asset & {
  tenant_id: string;
  notes: string | null;
  assertions: AssetAssertion[];
  relationships: Relationship[];
};

export type Summary = {
  total: number;
  by_kind: Record<string, number>;
  by_governance: Record<string, number>;
};

export type Coverage = {
  connector_id: string;
  connection_id: string;
  plane: string;
  scope: string;
  state: "complete" | "partial" | "failed" | "not_supported" | "unknown";
  detail: string | null;
  run_id: string;
  collected_at: string;
};

export type ConnectionValidationResult = {
  scope: string;
  plane: string;
  label: string;
  region: string;
  state: "passed" | "failed" | "unknown" | "not_applicable";
  detail: string;
  coverage_mode?: "automatic" | "selected";
  observed_at?: string;
  discovered_regions?: string[];
  not_enabled_regions?: string[];
  excluded_enabled_regions?: string[];
  subscription_id?: string;
  subscription_name?: string;
  project_id?: string;
  project_name?: string;
  project_number?: string;
  repository_id?: number;
  repository_full_name?: string;
};

export type ConnectionValidation = {
  id?: string;
  started_at: string;
  completed_at: string;
  health_state: "healthy" | "partial" | "unhealthy";
  credential_state: "passed" | "failed";
  account_id_observed: string | null;
  results: ConnectionValidationResult[];
  summary: string;
};

export type ConnectionCoveragePlan = {
  scope: string;
  plane: string;
  label: string;
  region: string;
  permissions: string[];
  validation_state: "not_validated";
  repository_id?: number;
  repository_node_id?: string;
  repository_full_name?: string;
};

export type GitHubRepositoryBoundary = {
  id: number;
  node_id: string;
  name: string;
  full_name: string;
  owner_id: number;
  owner_login: string;
  private: boolean;
  archived: boolean;
  default_branch: string | null;
};

export type Connection = {
  id: string;
  provider: "aws" | "azure" | "gcp" | "github";
  display_name: string;
  lifecycle_state: "active" | "disabled";
  health_state: "unknown" | "healthy" | "partial" | "unhealthy" | "disabled";
  validation_state?: "idle" | "running";
  source_collection_state?: "idle" | "running";
  last_source_collection?: GitHubSourceCollection | null;
  deployment_collection_state?: "idle" | "running";
  last_deployment_collection?: GcpDeploymentCollection | AzureDeploymentCollection | AwsDeploymentCollection | null;
  setup_capabilities: {
    cloudformation_quick_create: boolean;
    azure_cloud_shell: boolean;
    gcp_cloud_shell: boolean;
    github_app: boolean;
  };
  credential_reference:
    | {
        type: "aws_assume_role";
        role_arn: string;
      }
    | {
        type: "azure_multitenant_app";
        client_id: string;
        service_principal_id?: string;
      }
    | {
        type: "gcp_service_account";
        principal_email: string;
        principal_unique_id?: string;
      }
    | {
        type: "github_app_installation";
        app_id: number;
        app_slug: string;
        installation_id?: number;
      };
  declared_scopes: string[];
  coverage_plan: ConnectionCoveragePlan[];
  configuration: {
    account_id?: string;
    partition?: "aws" | "aws-us-gov" | "aws-cn";
    deployment_region?: string;
    coverage_mode?: "automatic" | "selected" | "selected-subscriptions" | "selected-projects" | "exact-installation-repositories";
    regions?: string[];
    role_name?: string;
    stack_scopes?: string[];
    tenant_id?: string;
    cloud?: "AzureCloud";
    subscriptions?: Array<{ id: string; name: string }>;
    projects?: Array<{ id: string; name: string; number: string }>;
    account_login?: string;
    account_type?: string;
    installation_repository_selection?: "all" | "selected";
    repositories?: GitHubRepositoryBoundary[];
    installer?: { id: number; login: string };
    onboarding?: {
      method: "cloudformation_quick_create" | "azure_cloud_shell" | "gcp_cloud_shell" | "github_app_installation";
      template_version?: string;
      template_sha256?: string;
      principal_arn?: string;
      script_version?: string;
      script_sha256?: string;
      client_id?: string;
      principal_email?: string;
      published_at?: string;
      url_expires_at?: string;
      created_at?: string;
      install_expires_at?: string;
      installation_id?: number;
      oauth_expires_at?: string;
      completed_at?: string;
    };
  };
  created_at?: string;
  updated_at?: string;
  last_validated_at?: string | null;
  last_validation: ConnectionValidation | null;
};

export type GitHubSourceCollectionRepository = {
  repository_id: number;
  repository: string;
  state: "complete" | "partial" | "failed";
  detail?: string;
  revision?: string;
  files?: number;
  bytes?: number;
  correlation?: CodeToCloudCorrelationSummary;
};

export type GitHubSourceCollection = {
  connection_id: string;
  state: "complete" | "partial" | "failed";
  completed_at: string;
  repository_count: number;
  failed_count: number;
  partial_count: number;
  repositories: GitHubSourceCollectionRepository[];
  detail?: string;
};

export type GcpDeploymentCollection = {
  connection_id: string;
  state: "complete" | "partial" | "failed";
  completed_at: string;
  project_count: number;
  failed_count: number;
  partial_count: number;
  projects: Array<{
    project_id: string;
    project_number?: string;
    state: "complete" | "partial" | "failed";
    assets?: number;
    ai_workloads?: number;
  }>;
  detail?: string;
};

export type AzureDeploymentCollection = {
  connection_id: string;
  state: "complete" | "partial" | "failed";
  completed_at: string;
  subscription_count: number;
  failed_count: number;
  partial_count: number;
  subscriptions: Array<{
    subscription_id: string;
    state: "complete" | "partial" | "failed";
    assets?: number;
    ai_workloads?: number;
  }>;
  detail?: string;
};

export type AwsDeploymentCollection = {
  connection_id: string;
  state: "complete" | "partial" | "failed";
  completed_at: string;
  region_count: number;
  failed_count: number;
  partial_count: number;
  regions: Array<{
    region: string;
    state: "complete" | "partial" | "failed";
    assets?: number;
    ai_workloads?: number;
  }>;
  detail?: string;
};

export type AwsCloudFormationLaunch = {
  launch_url: string;
  stack_name: string;
  stack_region: string;
  template_version: string;
  template_sha256: string;
  expires_at: string;
  validation_status: "started" | "already_running";
};

export type AwsConnectionCreate = {
  provider: "aws";
  display_name: string;
  account_id: string;
  partition: "aws" | "aws-us-gov" | "aws-cn";
  deployment_region: string;
  coverage_mode: "automatic" | "selected";
  regions: string[];
  declared_scopes: string[];
};

export type AzureConnectionCreate = {
  provider: "azure";
  display_name: string;
  tenant_id: string;
  cloud: "AzureCloud";
  declared_scopes: string[];
};

export type AzureSetupLaunch = {
  consent_url: string;
  cloud_shell_url: string;
  script_url: string;
  setup_command: string;
  script_version: string;
  script_sha256: string;
  expires_at: string;
};

export type GcpConnectionCreate = {
  provider: "gcp";
  display_name: string;
  declared_scopes: string[];
};

export type GcpSetupLaunch = {
  cloud_shell_url: string;
  script_url: string;
  setup_command: string;
  script_version: string;
  script_sha256: string;
  principal_email: string;
  expires_at: string;
};

export type GitHubConnectionCreate = {
  provider: "github";
  display_name: string;
  declared_scopes: string[];
};

export type GitHubSetupLaunch = {
  install_url: string;
  app_slug: string;
  expires_at: string;
};

export type FindingSeverity =
  | "unknown"
  | "informational"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type FindingState = "open" | "resolved" | "suppressed" | "unknown";

export type Finding = {
  id: string;
  connector_id: string;
  connection_id: string;
  scope_key: string;
  source_uid: string;
  rule_uid: string;
  title: string;
  description: string | null;
  risk: string | null;
  remediation: string | null;
  remediation_references: string[];
  severity: FindingSeverity;
  state: FindingState;
  evaluation_result: string;
  class_uid: number;
  class_name: string;
  source_observed_at: string;
  evidence: Evidence;
  attributes: Record<string, unknown>;
  resolution_reason: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_changed_at: string;
  last_observed_run_id: string;
  resource_count: number;
};

export type FindingResource = {
  uid: string;
  name: string | null;
  resource_type: string | null;
  provider: string | null;
  account_uid: string | null;
  region: string | null;
};

export type FindingObservation = {
  run_id: string;
  scope_key: string;
  collected_at: string;
  source_observed_at: string;
  severity: FindingSeverity;
  state: FindingState;
  evaluation_result: string;
  evidence: Evidence;
  attributes: Record<string, unknown>;
  affected_resources: FindingResource[];
  compliance: Record<string, string[]>;
};

export type FindingDetail = Finding & {
  resources: FindingResource[];
  compliance: Record<string, string[]>;
  observations: FindingObservation[];
};

export type FindingSummary = {
  total: number;
  by_state: Record<string, number>;
  open_by_severity: Record<string, number>;
};

export type IssueState = "open" | "resolved" | "unknown";

export type Issue = {
  id: string;
  correlation_key: string;
  rule_uid: string;
  title: string;
  description: string;
  risk: string;
  remediation: string;
  severity: FindingSeverity;
  state: IssueState;
  confidence: number;
  attributes: Record<string, unknown>;
  resolution_reason: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_changed_at: string;
  last_evaluated_at: string;
  finding_count: number;
  detection_count: number;
  activity_count: number;
  asset_count: number;
};

export type IssueFinding = {
  id: string;
  rule_uid: string;
  title: string;
  severity: FindingSeverity;
  state: FindingState;
  evidence: Evidence;
  role: string;
};

export type IssuePathNode = {
  position: number;
  role: string;
  id: string;
  kind: string;
  natural_key: string;
  display_name: string;
  assertion_type: string;
  confidence: number;
  evidence: Evidence;
};

export type IssuePathEdge = {
  position: number;
  id: string;
  kind: string;
  category: string;
  assertion_type: string;
  confidence: number;
  evidence: Evidence;
  withdrawn_at: string | null;
  source_id: string;
  target_id: string;
};

export type IssueDetection = {
  id: string;
  rule_uid: string;
  title: string;
  description: string;
  risk: string;
  investigation_guidance: string;
  severity: FindingSeverity;
  state: string;
  confidence: number;
  attributes: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
  role: string;
};

export type IssueActivityActor = {
  external_uid: string;
  display_name: string | null;
  asset_id: string | null;
  correlation: string;
  confidence: number;
};

export type IssueActivity = {
  id: string;
  category: string;
  outcome: string;
  activity_name: string;
  title: string;
  provider: string;
  occurred_at: string;
  evidence: Evidence;
  attributes: Record<string, unknown>;
  role: string;
  actors: IssueActivityActor[];
};

export type IssueDetail = Issue & {
  findings: IssueFinding[];
  detections: IssueDetection[];
  activities: IssueActivity[];
  path_nodes: IssuePathNode[];
  path_edges: IssuePathEdge[];
};

export type IssueSummary = {
  total: number;
  by_state: Record<string, number>;
  open_by_severity: Record<string, number>;
};

export type IssueEvaluation = {
  rule_uid: string;
  state: Coverage["state"];
  confirmed_issues: number;
  incomplete_candidates: number;
  ambiguous_resource_references: number;
  detail: string | null;
  evaluated_at: string;
};

export type CodeToCloudContext = {
  id: string;
  natural_key: string;
  display_name: string;
  assertion_type: string;
  confidence: number;
};

export type CodeToCloudModel = CodeToCloudContext & {
  relationship_source: "workload" | "agent";
};

export type CodeToCloudAction = {
  relationship_id: string;
  kind: "can_read" | "can_write" | "can_invoke";
  assertion_type: string;
  confidence: number;
  operation: string | null;
  target_id: string;
  target_kind: string;
  target_natural_key: string;
  target_name: string;
  execution_status: string;
};

export type CodeToCloudTool = CodeToCloudContext & {
  provider: string | null;
  operation: string | null;
  execution_status: string;
  actions: CodeToCloudAction[];
};

export type CodeToCloudFinding = {
  id: string;
  title: string;
  severity: FindingSeverity;
  rule_uid: string;
  source_path: string | null;
  source_line: string | null;
  applicability: "artifact_included" | "repository_only";
  import_chain: string[] | null;
};

export type CodeToCloudVulnerabilityCoverage = {
  state: "complete" | "partial" | "failed" | "unknown";
  detail: string | null;
  connector_id: string;
  connection_id: string;
  run_id: string;
  collected_at: string;
  artifact_kind: string;
  artifact_locator: string;
  artifact_digest: string | null;
  artifact_identity_status: "matched" | "not_matched" | "not_evaluated";
  artifact_identity_method: "exact_locator" | "exact_digest" | null;
};

export type CodeToCloudVulnerability = {
  id: string;
  vulnerability_id: string;
  title: string | null;
  severity: FindingSeverity;
  state: FindingState;
  cvss_score: number | null;
  fix_state: "fixed" | "not_fixed" | "wont_fix" | "unknown";
  fixed_versions: string[];
  exploit_state: "known_exploited" | "public_exploit" | "no_known_exploit" | "unknown";
  match_method: string;
  match_confidence: number;
  scanner: string;
  source_count: number;
  component_id: string | null;
  component_name: string | null;
  component_purl: string | null;
};

export type CodeToCloudDeployment = {
  id: string;
  assertion_type: string;
  confidence: number;
  attributes: Record<string, unknown>;
  evidence: Evidence;
  workload_id: string;
  workload_natural_key: string;
  workload_name: string;
  workload_attributes: Record<string, unknown>;
  repository_id: string;
  repository_natural_key: string;
  repository_name: string;
  agent: CodeToCloudContext | null;
  tools: CodeToCloudTool[];
  models: CodeToCloudModel[];
  identity: CodeToCloudContext | null;
  code_findings: CodeToCloudFinding[];
  vulnerability_coverage: CodeToCloudVulnerabilityCoverage | null;
  artifact_vulnerability_count: number;
  artifact_vulnerability_id_count: number;
  artifact_vulnerabilities: CodeToCloudVulnerability[];
};

export type CodeToCloudCorrelationSummary = {
  declarations: number;
  proven: number;
  ambiguous: number;
  unmatched: number;
  targets_evaluated: number;
};

export type CodeToCloudCandidate = {
  status: "proven" | "ambiguous" | "unmatched";
  service: string;
  construct_id: string;
  deployment_identifier: string;
  source_path: string;
  source_line: number;
  match_basis: string[];
  matched_workloads: string[];
  matched_workload_count: number;
};

export type CodeToCloudObservation = {
  connection_id: string;
  repository_id: string | null;
  repository_natural_key: string;
  repository_name: string | null;
  source_state: "complete" | "partial" | "failed" | null;
  source_detail: string | null;
  source_run_id: string | null;
  source_collected_at: string | null;
  analysis_state: "complete" | "partial" | "failed" | null;
  analysis_detail: string | null;
  analysis_run_id: string | null;
  analysis_collected_at: string | null;
  correlation_summary: CodeToCloudCorrelationSummary | null;
  correlation_candidates: CodeToCloudCandidate[];
  evidence: Evidence | null;
};

export type Vulnerability = {
  id: string;
  canonical_key: string;
  vulnerability_id: string;
  component_kind: string;
  component_natural_key: string;
  component_asset_id: string | null;
  target_kind: string;
  target_natural_key: string;
  target_asset_id: string | null;
  state: FindingState;
  first_seen_at: string;
  last_seen_at: string;
  last_changed_at: string;
  aliases: string[];
  title: string | null;
  description: string | null;
  severity: FindingSeverity;
  cvss_score: number | null;
  cvss_vector: string | null;
  fix_state: "fixed" | "not_fixed" | "wont_fix" | "unknown";
  fixed_versions: string[];
  exploit_state: "known_exploited" | "public_exploit" | "no_known_exploit" | "unknown";
  match_method: string;
  match_confidence: number;
  database_version: string | null;
  database_built_at: string | null;
  scanner: string;
  scanner_connection: string;
  component_correlated: boolean;
  target_correlated: boolean;
  source_count: number;
  component_name: string | null;
  component_attributes: Record<string, unknown> | null;
  target_name: string | null;
};

export type VulnerabilityObservation = {
  connector_id: string;
  connection_id: string;
  source_uid: string;
  scope_key: string;
  aliases: string[];
  title: string | null;
  description: string | null;
  severity: FindingSeverity;
  state: FindingState;
  cvss_score: number | null;
  cvss_vector: string | null;
  fix_state: Vulnerability["fix_state"];
  fixed_versions: string[];
  exploit_state: Vulnerability["exploit_state"];
  match_method: string;
  match_confidence: number;
  database_version: string | null;
  database_built_at: string | null;
  source_observed_at: string;
  evidence: Evidence;
  attributes: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
  last_observed_run_id: string;
  withdrawn_at: string | null;
};

export type VulnerabilityDetail = {
  id: string;
  canonical_key: string;
  vulnerability_id: string;
  state: FindingState;
  first_seen_at: string;
  last_seen_at: string;
  last_changed_at: string;
  resolution_reason: string | null;
  component: {
    kind: string;
    natural_key: string;
    asset_id: string | null;
    display_name: string | null;
    attributes: Record<string, unknown> | null;
  };
  target: {
    kind: string;
    natural_key: string;
    asset_id: string | null;
    display_name: string | null;
  };
  observations: VulnerabilityObservation[];
};

export type VulnerabilitySummary = {
  total: number;
  by_state: Record<string, number>;
  open_vulnerability_ids: number;
  open_by_severity: Record<string, number>;
  open_by_fix_state: Record<string, number>;
  open_by_exploit_state: Record<string, number>;
};

export type ActivityCategory =
  | "model_invocation"
  | "agent_invocation"
  | "retrieval"
  | "tool_invocation"
  | "ai_app_sign_in"
  | "admin_change"
  | "data_access"
  | "other";

export type RuntimeActivity = {
  id: string;
  connector_id: string;
  connection_id: string;
  run_id: string;
  scope_key: string;
  source_uid: string;
  category: ActivityCategory;
  activity_name: string;
  title: string;
  outcome: "success" | "failure" | "unknown";
  provider: string;
  account_uid: string | null;
  region: string | null;
  occurred_at: string;
  source_observed_at: string;
  session_uid: string | null;
  trace_uid: string | null;
  evidence: Evidence;
  attributes: Record<string, unknown>;
  ingested_at: string;
  actor_uid: string | null;
  actor_name: string | null;
  actor_asset_id: string | null;
  entity_count: number;
  correlated_entity_count: number;
};

export type ActivityEntity = {
  position: number;
  role: "actor" | "agent" | "model" | "tool" | "workload" | "resource" | "application";
  external_uid: string;
  display_name: string | null;
  asset_kind: string | null;
  asset_natural_key: string | null;
  asset_id: string | null;
  correlation: "exact_identifier" | "explicit_context" | "unresolved";
  confidence: number;
  attributes: Record<string, unknown>;
  lifecycle_state: string | null;
  governance_status: Asset["governance_status"] | null;
  asset_display_name: string | null;
};

export type RuntimeActivityDetail = Omit<
  RuntimeActivity,
  "actor_uid" | "actor_name" | "actor_asset_id" | "entity_count" | "correlated_entity_count"
> & {
  entities: ActivityEntity[];
};

export type RuntimeActivitySummary = {
  total: number;
  last_24h: number;
  providers: number;
  failures: number;
  fixture_total: number;
  by_category: Partial<Record<ActivityCategory, number>>;
};

export type RuntimeDetection = {
  id: string;
  correlation_key: string;
  rule_uid: string;
  title: string;
  description: string;
  risk: string;
  investigation_guidance: string;
  severity: FindingSeverity;
  state: "open" | "resolved" | "unknown";
  confidence: number;
  attributes: Record<string, unknown>;
  resolution_reason: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_changed_at: string;
  last_evaluated_at: string;
  activity_count: number;
  asset_count: number;
};

export type RuntimeDetectionActivity = Omit<
  RuntimeActivity,
  "actor_uid" | "actor_name" | "actor_asset_id" | "entity_count" | "correlated_entity_count"
> & { role: string };

export type RuntimeDetectionAsset = {
  id: string;
  kind: string;
  natural_key: string;
  display_name: string;
  governance_status: Asset["governance_status"];
  lifecycle_state: string;
  role: string;
  assertion_type: string;
  confidence: number;
  attributes: Record<string, unknown>;
  evidence: Evidence;
};

export type RuntimeDetectionDetail = Omit<RuntimeDetection, "activity_count" | "asset_count"> & {
  activities: RuntimeDetectionActivity[];
  assets: RuntimeDetectionAsset[];
};

export type RuntimeDetectionSummary = {
  total: number;
  by_state: Record<string, number>;
  open_by_severity: Record<string, number>;
};

export type RuntimeDetectionEvaluation = {
  rule_uid: string;
  state: "complete" | "partial" | "failed" | "not_supported" | "unknown";
  confirmed_detections: number;
  incomplete_candidates: number;
  detail: string | null;
  evaluated_at: string;
};
