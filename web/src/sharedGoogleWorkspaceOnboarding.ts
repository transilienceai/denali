export const SHARED_GOOGLE_WORKSPACE_SCOPES = [
  "google_workspace.gemini_activity",
  "google_workspace.oauth_activity",
] as const;

export const GOOGLE_WORKSPACE_AUDIT_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly";
export const GOOGLE_WORKSPACE_ADMIN_CONSOLE_URL = "https://admin.google.com/ac/owl/domainwidedelegation";

export function sharedGoogleWorkspaceNotEnabled(error: unknown): boolean {
  return error instanceof Error && "status" in error && error.status === 404;
}

export function sharedGoogleWorkspaceHasFixedScopes(scopes: readonly string[]): boolean {
  return Array.isArray(scopes) && scopes.length === SHARED_GOOGLE_WORKSPACE_SCOPES.length &&
    SHARED_GOOGLE_WORKSPACE_SCOPES.every((scope) => scopes.includes(scope));
}

type WorkspaceBinding = {
  id: string;
  clerk_org_id: string;
  provider: string;
  target_id: string;
  customer_id: string;
  domain: string;
  admin_email: string;
  service_account: string;
  oauth_client_id: string;
  binding_revision: number;
};

type WorkspaceReadiness = WorkspaceBinding & {
  lifecycle_state: string;
  setup_state: string;
  health_state: string;
  declared_scopes: readonly string[];
  validated_scopes: readonly string[];
  job_state?: string | null;
  last_validated_at: string | null;
  validation_results?: readonly { scope: string; application_name: string; state: string }[];
};

export function sharedGoogleWorkspaceSameBinding(left: WorkspaceBinding, right: WorkspaceBinding): boolean {
  return (["id", "clerk_org_id", "provider", "target_id", "customer_id", "domain", "admin_email",
    "service_account", "oauth_client_id", "binding_revision"] as const).every((key) => left[key] === right[key]);
}

export function sharedGoogleWorkspaceAcceptValidation<T extends WorkspaceReadiness>(
  items: readonly T[], selected: T, result: T,
): T[] {
  // Authority changes advance the revision; a healthy repeat probe can preserve
  // it. Neither transition permits a selected target identity change.
  const sameAuthority = selected.lifecycle_state === result.lifecycle_state &&
    selected.setup_state === "ready" && result.setup_state === "ready" &&
    selected.health_state === "healthy" && result.health_state === "healthy" &&
    sharedGoogleWorkspaceHasFixedScopes(selected.declared_scopes) &&
    sharedGoogleWorkspaceHasFixedScopes(selected.validated_scopes) &&
    sharedGoogleWorkspaceHasFixedScopes(result.declared_scopes) &&
    sharedGoogleWorkspaceHasFixedScopes(result.validated_scopes);
  if (!Number.isSafeInteger(result.binding_revision) || result.binding_revision < selected.binding_revision ||
    (result.binding_revision === selected.binding_revision && !sameAuthority) ||
    !sharedGoogleWorkspaceSameBinding({ ...selected, binding_revision: result.binding_revision }, result)) {
    throw new Error("Workspace validation changed the selected target identity");
  }
  return items.map((item) => item.id === selected.id ? result : item);
}

export function sharedGoogleWorkspaceCanAttach(connection: WorkspaceReadiness | null, now: number = Date.now()): boolean {
  const validatedAt = connection?.last_validated_at ? Date.parse(connection.last_validated_at) : Number.NaN;
  return connection !== null && connection.provider === "google_workspace" &&
    connection.lifecycle_state === "active" && connection.setup_state === "ready" &&
    connection.health_state === "healthy" && !["queued", "running", "failed"].includes(connection.job_state ?? "") &&
    Number.isFinite(validatedAt) && validatedAt >= now - 15 * 60 * 1000 && validatedAt <= now + 60 * 1000 &&
    sharedGoogleWorkspaceHasFixedScopes(connection.declared_scopes) &&
    sharedGoogleWorkspaceHasFixedScopes(connection.validated_scopes) &&
    connection.validation_results?.length === 2 &&
    SHARED_GOOGLE_WORKSPACE_SCOPES.every((scope, index) => connection.validation_results?.some((result) =>
      result.scope === scope && result.application_name === ["gemini_in_workspace_apps", "token"][index] && result.state === "passed"));
}

export function sharedGoogleWorkspaceRequestDefinition(targetId: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(targetId)) {
    throw new Error("Select an admitted Google Workspace target");
  }
  return JSON.stringify({ target_id: targetId, declared_scopes: SHARED_GOOGLE_WORKSPACE_SCOPES });
}
