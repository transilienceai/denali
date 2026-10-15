import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { microsoftTenantId, parseSharedAzureSubscriptions, sharedMicrosoftReady, microsoftConsentUrl } from "../src/sharedMicrosoftOnboarding.ts";

const tenant = "22222222-2222-4222-8222-222222222222";
const sub = "33333333-3333-4333-8333-333333333333";
const client = "44444444-4444-4444-8444-444444444444";
const callback = "https://platform.example/internal/v1/connections/azure/setup/callback";
const state = "a".repeat(43);
const binding = { clientId: client, callbackUrl: callback };
const azureUrl = () => `https://login.microsoftonline.com/${tenant}/v2.0/adminconsent?${new URLSearchParams({ client_id: client, redirect_uri: callback, scope: "openid", state })}`;

test("Microsoft IDs and subscription selection remain exact and bounded", () => {
  assert.equal(microsoftTenantId(` ${tenant} `), tenant);
  assert.deepEqual(parseSharedAzureSubscriptions(sub), [{ id: sub }]);
  for (const value of ["", "*", `${sub},${sub}`, `${sub}/providers/x`, Array.from({ length: 9 }, () => sub).join("\n")]) assert.throws(() => parseSharedAzureSubscriptions(value));
});

test("shared attachment requires healthy current scope evidence", () => {
  const plan = { availability: "ready", health_state: "healthy", validated_scopes: ["azure.ai_services"] };
  assert.equal(sharedMicrosoftReady(plan, ["azure.ai_services"]), true);
  assert.equal(sharedMicrosoftReady(plan, []), false);
  assert.equal(sharedMicrosoftReady(plan, ["azure.ai_platform"]), false);
  for (const health_state of ["unknown", "partial", "unhealthy"]) assert.equal(sharedMicrosoftReady({ ...plan, health_state }, plan.validated_scopes), false);
  for (const availability of ["disabled", "needs_setup", "needs_validation"]) assert.equal(sharedMicrosoftReady({ ...plan, availability }, plan.validated_scopes), false);
});

test("only the exact tenant Microsoft consent URL can be launched", () => {
  const url = `https://login.microsoftonline.com/${tenant}/v2.0/adminconsent?state=synthetic`;
  assert.equal(microsoftConsentUrl(url, tenant), url);
  const legacyAzureUrl = url.replace("v2.0/adminconsent", "adminconsent");
  assert.equal(microsoftConsentUrl(azureUrl(), tenant, "azure", binding), azureUrl());
  assert.throws(() => microsoftConsentUrl(url, tenant, "azure"));
  assert.throws(() => microsoftConsentUrl(legacyAzureUrl, tenant, "azure", binding));
  assert.throws(() => microsoftConsentUrl(legacyAzureUrl, tenant, "entra"));
  for (const value of ["javascript:alert(1)", url.replace(tenant, sub), url.replace("https:", "http:"), url.replace("login.microsoftonline.com", "other.example"), `${url}#fragment`]) assert.throws(() => microsoftConsentUrl(value, tenant));
});

test("Azure requests only explicit openid with four unique bound query fields", () => {
  for (const scope of ["", "profile", "User.Read", "openid profile", "openid email", "openid offline_access", "https://graph.microsoft.com/.default", "openid "]) {
    const url = new URL(azureUrl()); url.searchParams.set("scope", scope);
    assert.throws(() => microsoftConsentUrl(url.href, tenant, "azure", binding));
  }
  for (const key of ["client_id", "redirect_uri", "scope", "state"]) {
    const missing = new URL(azureUrl()); missing.searchParams.delete(key);
    assert.throws(() => microsoftConsentUrl(missing.href, tenant, "azure", binding));
    const duplicate = new URL(azureUrl()); duplicate.searchParams.append(key, duplicate.searchParams.get(key)!);
    assert.throws(() => microsoftConsentUrl(duplicate.href, tenant, "azure", binding));
  }
  const extra = new URL(azureUrl()); extra.searchParams.set("resource", "https://graph.microsoft.com");
  assert.throws(() => microsoftConsentUrl(extra.href, tenant, "azure", binding));
  for (const value of ["x".repeat(31), "x".repeat(129), "a b".repeat(12), "a/b".repeat(12), "a+b".repeat(12)]) {
    const url = new URL(azureUrl()); url.searchParams.set("state", value);
    assert.throws(() => microsoftConsentUrl(url.href, tenant, "azure", binding));
  }
  for (const value of ["a".repeat(32), "_-A0".repeat(32)]) {
    const url = new URL(azureUrl()); url.searchParams.set("state", value);
    assert.equal(microsoftConsentUrl(url.href, tenant, "azure", binding), url.href);
  }
});

test("Azure client and registered callback must match authenticated setup metadata", () => {
  assert.throws(() => microsoftConsentUrl(azureUrl(), tenant, "azure"));
  for (const clientId of [sub, "*", ""]) assert.throws(() => microsoftConsentUrl(azureUrl(), tenant, "azure", { ...binding, clientId }));
  assert.throws(() => microsoftConsentUrl(azureUrl(), tenant, "azure", { ...binding, callbackUrl: callback.replace("platform.example", "other.example") }));
  for (const callbackUrl of [callback.replace("azure", "entra"), "http://platform.example/internal/v1/connections/azure/setup/callback", `${callback}?extra=1`, `${callback}#fragment`, callback.replace("platform.example", "user@platform.example"), callback.replace("platform.example", "platform.example:8443")]) {
    assert.throws(() => microsoftConsentUrl(azureUrl(), tenant, "azure", { ...binding, callbackUrl }));
    const matchedButUnsafe = new URL(azureUrl()); matchedButUnsafe.searchParams.set("redirect_uri", callbackUrl);
    assert.throws(() => microsoftConsentUrl(matchedButUnsafe.href, tenant, "azure", { ...binding, callbackUrl }));
  }
  for (const origin of ["https://platform-dev.example", "https://platform-prod.example"]) {
    const callbackUrl = origin + "/internal/v1/connections/azure/setup/callback";
    const url = new URL(azureUrl()); url.searchParams.set("redirect_uri", callbackUrl);
    assert.equal(microsoftConsentUrl(url.href, tenant, "azure", { ...binding, callbackUrl }), url.href);
  }
});

test("shared Microsoft UI preserves same-origin boundaries and customer execution approval", () => {
  const api = readFileSync(new URL("../src/api.ts", import.meta.url), "utf8");
  const panel = readFileSync(new URL("../src/SharedMicrosoftPilot.tsx", import.meta.url), "utf8");
  const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.match(api, /const API_BASE = "\/api"/);
  assert.match(panel, /creation\.current\.id/);
  assert.match(panel, /Fixed Microsoft Graph application bundle/);
  assert.match(panel, /Run it yourself in Azure Cloud Shell only after approving Reader assignments/);
  assert.match(panel, /This view checks access status when you return/);
  assert.match(panel, /useSharedStatusPolling/);
  assert.match(panel, /Azure covers at most 24 hours; Entra covers at most 7 days per run/);
  assert.match(panel, /Microsoft tenant\/subscriptions approved for this organization/);
  assert.match(app, /provider === "azure" \|\| provider === "entra"/);
  assert.match(app, /<SharedMicrosoftPilot provider=\{provider\}/);
  assert.doesNotMatch(panel, /client_secret|access_token|modal\.run|exec\(/);
});
