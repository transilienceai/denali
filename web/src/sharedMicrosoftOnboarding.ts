const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const SHARED_AZURE_SCOPES = ["azure.ai_services", "azure.ai_platform", "azure.ai_activity", "azure.agent_runtime_activity", "azure.code_to_cloud"];
export const SHARED_ENTRA_SCOPES = ["entra.ai_applications", "entra.permissions", "entra.sign_ins", "entra.directory_audits"];

export function microsoftTenantId(value: string): string {
  if (!UUID_PATTERN.test(value.trim())) throw new Error("Enter the exact Microsoft tenant UUID");
  return value.trim().toLowerCase();
}

export function parseSharedAzureSubscriptions(value: string): Array<{ id: string }> {
  const ids = value.split(/\n|,/).filter((line) => line.trim()).map(microsoftTenantId);
  if (!ids.length || ids.length > 8 || new Set(ids).size !== ids.length) {
    throw new Error("Select 1–8 unique Azure subscription UUIDs");
  }
  return ids.sort().map((id) => ({ id }));
}

export function sharedMicrosoftReady(connection: { availability: string; health_state: string; validated_scopes: string[] }, scopes: string[]): boolean {
  return connection.availability === "ready" && connection.health_state === "healthy" &&
    scopes.length > 0 && scopes.every((scope) => connection.validated_scopes.includes(scope));
}

export function microsoftConsentUrl(value: string, tenantId: string, provider: "azure" | "entra" = "entra", azureBinding?: { clientId: string; callbackUrl: string }): string {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.hostname !== "login.microsoftonline.com" ||
    url.port || url.username || url.password ||
    url.pathname !== `/${microsoftTenantId(tenantId)}/v2.0/adminconsent` || url.hash) {
    throw new Error("Microsoft consent response is invalid");
  }
  if (provider === "azure") {
    // Azure bootstrap requests only OIDC sign-in, not the legacy endpoint's
    // static permission bundle. Bind it to authenticated Platform setup metadata.
    if (!azureBinding) throw new Error("Microsoft consent response is invalid");
    const callback = new URL(azureBinding.callbackUrl);
    const keys = [...url.searchParams.keys()].sort();
    if (callback.protocol !== "https:" || !callback.hostname || callback.port ||
      callback.username || callback.password || callback.search || callback.hash ||
      callback.pathname !== "/internal/v1/connections/azure/setup/callback" ||
      keys.join(",") !== "client_id,redirect_uri,scope,state" ||
      url.searchParams.get("client_id") !== microsoftTenantId(azureBinding.clientId) ||
      url.searchParams.get("redirect_uri") !== azureBinding.callbackUrl ||
      url.searchParams.get("scope") !== "openid" ||
      !/^[A-Za-z0-9_-]{32,128}$/.test(url.searchParams.get("state") ?? "")) {
      throw new Error("Microsoft consent response is invalid");
    }
  }
  return url.href;
}
