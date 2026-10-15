import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { api, configureApiTokenProvider } from "../src/api.ts";
import {
  GOOGLE_WORKSPACE_ADMIN_CONSOLE_URL,
  GOOGLE_WORKSPACE_AUDIT_SCOPE,
  SHARED_GOOGLE_WORKSPACE_SCOPES,
  sharedGoogleWorkspaceAcceptValidation,
  sharedGoogleWorkspaceCanAttach,
  sharedGoogleWorkspaceHasFixedScopes,
  sharedGoogleWorkspaceNotEnabled,
  sharedGoogleWorkspaceRequestDefinition,
  sharedGoogleWorkspaceSameBinding,
} from "../src/sharedGoogleWorkspaceOnboarding.ts";

const targetId = "9f0b1f03-3045-4232-9291-c0f6dd3f6f58";
const now = Date.parse("2026-10-14T12:00:00Z");
const connection = {
  id: "d5d0e536-df0d-4999-bc79-79bf6af8c320",
  clerk_org_id: "org_test_fixture",
  provider: "google_workspace",
  target_id: targetId,
  customer_id: "C01example",
  domain: "example.com",
  admin_email: "administrator@example.com",
  service_account: "workspace-reader@platform-example.iam.gserviceaccount.com",
  oauth_client_id: "123456789012345678901",
  binding_revision: 1,
  lifecycle_state: "active",
  setup_state: "ready",
  health_state: "healthy",
  declared_scopes: [...SHARED_GOOGLE_WORKSPACE_SCOPES],
  validated_scopes: [...SHARED_GOOGLE_WORKSPACE_SCOPES],
  last_validated_at: "2026-10-14T11:59:00Z",
  validation_results: [
    { scope: "google_workspace.gemini_activity", application_name: "gemini_in_workspace_apps", state: "passed" },
    { scope: "google_workspace.oauth_activity", application_name: "token", state: "passed" },
  ],
};

test("Workspace always requests the complete two-plane bundle and sole audit-read scope", () => {
  assert.equal(GOOGLE_WORKSPACE_AUDIT_SCOPE, "https://www.googleapis.com/auth/admin.reports.audit.readonly");
  assert.equal(GOOGLE_WORKSPACE_ADMIN_CONSOLE_URL, "https://admin.google.com/ac/owl/domainwidedelegation");
  assert.equal(sharedGoogleWorkspaceHasFixedScopes(SHARED_GOOGLE_WORKSPACE_SCOPES), true);
  assert.equal(sharedGoogleWorkspaceHasFixedScopes([...SHARED_GOOGLE_WORKSPACE_SCOPES].reverse()), true);
  for (const scopes of [[], [SHARED_GOOGLE_WORKSPACE_SCOPES[0]], [SHARED_GOOGLE_WORKSPACE_SCOPES[0], SHARED_GOOGLE_WORKSPACE_SCOPES[0]],
    [...SHARED_GOOGLE_WORKSPACE_SCOPES, "google_workspace.directory_tokens"], ["*"], [GOOGLE_WORKSPACE_AUDIT_SCOPE]]) {
    assert.equal(sharedGoogleWorkspaceHasFixedScopes(scopes), false);
  }
});

test("Workspace attachment requires fresh ready healthy proof for both planes", () => {
  assert.equal(sharedGoogleWorkspaceCanAttach(connection, now), true);
  assert.equal(sharedGoogleWorkspaceCanAttach({ ...connection, job_state: "succeeded" }, now), true);
  for (const patch of [
    { provider: "gcp" }, { lifecycle_state: "disabled" }, { setup_state: "pending_authorization" },
    { health_state: "unknown" }, { health_state: "partial" }, { health_state: "unhealthy" },
    { declared_scopes: [SHARED_GOOGLE_WORKSPACE_SCOPES[0]] }, { validated_scopes: [] },
    { validated_scopes: [SHARED_GOOGLE_WORKSPACE_SCOPES[0]] },
    { validated_scopes: [...SHARED_GOOGLE_WORKSPACE_SCOPES, "unexpected.scope"] },
    { job_state: "queued" }, { job_state: "running" }, { job_state: "failed" },
    { last_validated_at: null }, { last_validated_at: "invalid" },
    { last_validated_at: "2026-10-14T11:44:59Z" }, { last_validated_at: "2026-10-14T13:00:00Z" },
    { validation_results: [] }, { validation_results: [{ ...connection.validation_results[0], state: "failed" }, connection.validation_results[1]] },
  ]) assert.equal(sharedGoogleWorkspaceCanAttach({ ...connection, ...patch }, now), false, JSON.stringify(patch));
  assert.equal(sharedGoogleWorkspaceCanAttach(null, now), false);
});

test("status proof from another org, target or changed identity cannot enable attachment", () => {
  assert.equal(sharedGoogleWorkspaceSameBinding(connection, { ...connection }), true);
  for (const key of ["id", "clerk_org_id", "provider", "target_id", "customer_id", "domain", "admin_email", "service_account", "oauth_client_id"] as const) {
    assert.equal(sharedGoogleWorkspaceSameBinding(connection, { ...connection, [key]: "changed" }), false, key);
  }
  assert.equal(sharedGoogleWorkspaceSameBinding(connection, { ...connection, binding_revision: 2 }), false);
});

test("validation advances selection revision and enables attachment without manual refresh", () => {
  const pending = { ...connection, binding_revision: 1, setup_state: "pending_authorization",
    health_state: "unknown", validated_scopes: [], last_validated_at: null, validation_results: [] };
  const validated = { ...connection, binding_revision: 2 };
  const inventory = sharedGoogleWorkspaceAcceptValidation([pending], pending, validated);
  assert.equal(sharedGoogleWorkspaceSameBinding(inventory[0], validated), true);
  assert.equal(sharedGoogleWorkspaceCanAttach(inventory[0], now), true);
  const refreshed = { ...validated, last_validated_at: "2026-10-14T12:00:00Z" };
  assert.deepEqual(sharedGoogleWorkspaceAcceptValidation([validated], validated, refreshed), [refreshed]);
  for (const change of [{ customer_id: "C02other" }, { clerk_org_id: "org_other" },
    { binding_revision: 1 }, { binding_revision: 1.5 }]) {
    assert.throws(() => sharedGoogleWorkspaceAcceptValidation([pending], pending, { ...validated, ...change }));
  }
});

test("setup retry identity contains only the admitted target and fixed scope bundle", () => {
  assert.deepEqual(JSON.parse(sharedGoogleWorkspaceRequestDefinition(targetId)), {
    target_id: targetId, declared_scopes: SHARED_GOOGLE_WORKSPACE_SCOPES,
  });
  assert.equal(sharedGoogleWorkspaceRequestDefinition(targetId), sharedGoogleWorkspaceRequestDefinition(targetId));
  assert.equal(JSON.parse(sharedGoogleWorkspaceRequestDefinition("0198fdbd-2222-7333-8444-0123456789ab")).target_id, "0198fdbd-2222-7333-8444-0123456789ab");
  for (const id of ["", "*", "example.com", "org_test_fixture", "targets/arbitrary", `${targetId}/extra`]) {
    assert.throws(() => sharedGoogleWorkspaceRequestDefinition(id));
  }
});

test("only an explicit 404 hides the shared Workspace panel", () => {
  assert.equal(sharedGoogleWorkspaceNotEnabled(Object.assign(new Error("disabled"), { status: 404 })), true);
  for (const status of [400, 401, 403, 409, 422, 502, 503]) {
    assert.equal(sharedGoogleWorkspaceNotEnabled(Object.assign(new Error("failed"), { status })), false);
  }
  assert.equal(sharedGoogleWorkspaceNotEnabled(new Error("network failure")), false);
});

test("Workspace client uses authenticated same-origin named routes and exact request bodies", async () => {
  const originalFetch = globalThis.fetch;
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  globalThis.fetch = async (input, init) => {
    requests.push({ url: String(input), init });
    return new Response(JSON.stringify({ items: [], ...connection }), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  configureApiTokenProvider(async () => "fixture-session");
  try {
    await api.sharedGoogleWorkspaceConfig();
    await api.sharedGoogleWorkspaceInventory();
    await api.startSharedGoogleWorkspaceSetup({ target_id: targetId, request_id: targetId, declared_scopes: [...SHARED_GOOGLE_WORKSPACE_SCOPES] });
    await api.sharedGoogleWorkspaceStatus("selected/id");
    await api.validateSharedGoogleWorkspace("selected/id");
    await api.useSharedGoogleWorkspaceInDenali("selected/id");
    assert.deepEqual(requests.map((request) => request.url), [
      "/api/v1/shared/connections/google-workspace/config",
      "/api/v1/shared/connections/google-workspace/inventory",
      "/api/v1/shared/connections/google-workspace/setup",
      "/api/v1/shared/connections/google-workspace/selected%2Fid/status",
      "/api/v1/shared/connections/google-workspace/selected%2Fid/validate",
      "/api/v1/shared/connections/google-workspace/selected%2Fid/use-in-denali",
    ]);
    assert.deepEqual(JSON.parse(String(requests[2].init?.body)), {
      target_id: targetId, request_id: targetId, declared_scopes: SHARED_GOOGLE_WORKSPACE_SCOPES,
    });
    assert.equal(requests[4].init?.body, undefined);
    assert.equal(requests[5].init?.body, "{}");
    assert.deepEqual(requests.map((request) => request.init?.method ?? "GET"), ["GET", "GET", "POST", "GET", "POST", "POST"]);
    for (const request of requests) assert.equal(new Headers(request.init?.headers).get("Authorization"), "Bearer fixture-session");
  } finally {
    globalThis.fetch = originalFetch;
    configureApiTokenProvider(async () => null);
  }
});

test("shared Workspace UI keeps authorization external, attachment explicit, and native detail separate", () => {
  const panel = readFileSync(new URL("../src/SharedGoogleWorkspacePilot.tsx", import.meta.url), "utf8");
  const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  const sharedDetail = app.slice(app.indexOf("function SharedGoogleWorkspaceConnectionDetail"), app.indexOf("function GoogleWorkspaceConnectionDetail"));
  assert.match(panel, /creation\.current\.id/);
  assert.match(panel, /sharedGoogleWorkspaceSameBinding\(selected, current\)/);
  assert.match(panel, /sharedGoogleWorkspaceCanAttach\(current\)/);
  assert.match(panel, /api\.useSharedGoogleWorkspaceInDenali\(selected\.id\)/);
  assert.match(panel, /Numeric OAuth client ID/);
  assert.match(panel, /selected\.service_account/);
  assert.match(panel, /GOOGLE_WORKSPACE_ADMIN_CONSOLE_URL/);
  assert.match(panel, /I authorized it — verify access/);
  assert.match(panel, /const validatedItems = sharedGoogleWorkspaceAcceptValidation\(items, selected, result\)/);
  assert.match(panel, /setItems\(validatedItems\)/);
  assert.doesNotMatch(panel, /type="checkbox"|modal\.run|createConnection\(|completeGoogleWorkspaceSetup\(|callback/);
  assert.ok(app.indexOf('connection.credential_reference.type === "platform_shared_google_workspace"') < app.indexOf('if (connection.provider === "google_workspace") return'));
  assert.match(sharedDetail, /onValidate/);
  assert.match(sharedDetail, /onCollect/);
  assert.match(sharedDetail, /configuration\.customer_id/);
  assert.match(sharedDetail, /Disable Denali use/);
  assert.match(sharedDetail, /Delete Denali configuration/);
  assert.doesNotMatch(sharedDetail, /onComplete|google_workspace_admin_authorization|Open Google Admin Console/);
  assert.match(app, /<SharedGoogleWorkspacePilot canWrite=\{canWrite\} onChanged=\{onChanged\}/);
  assert.match(app, /function GoogleWorkspaceConnectionDetail/);
});
