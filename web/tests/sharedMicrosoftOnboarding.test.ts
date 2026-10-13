import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { microsoftTenantId, parseSharedAzureSubscriptions, sharedMicrosoftReady, microsoftConsentUrl } from "../src/sharedMicrosoftOnboarding.ts";

const tenant = "22222222-2222-4222-8222-222222222222";
const sub = "33333333-3333-4333-8333-333333333333";

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
  const azureUrl = url.replace("v2.0/adminconsent", "adminconsent");
  assert.equal(microsoftConsentUrl(azureUrl, tenant, "azure"), azureUrl);
  assert.throws(() => microsoftConsentUrl(url, tenant, "azure"));
  assert.throws(() => microsoftConsentUrl(azureUrl, tenant, "entra"));
  for (const value of ["javascript:alert(1)", url.replace(tenant, sub), url.replace("https:", "http:"), url.replace("login.microsoftonline.com", "other.example"), `${url}#fragment`]) assert.throws(() => microsoftConsentUrl(value, tenant));
});

test("shared Microsoft UI preserves same-origin boundaries and customer execution approval", () => {
  const api = readFileSync(new URL("../src/api.ts", import.meta.url), "utf8");
  const panel = readFileSync(new URL("../src/SharedMicrosoftPilot.tsx", import.meta.url), "utf8");
  const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.match(api, /const API_BASE = "\/api"/);
  assert.match(panel, /creation\.current\.id/);
  assert.match(panel, /Fixed Microsoft Graph application bundle/);
  assert.match(panel, /Run it yourself in Azure Cloud Shell only after approving Reader assignments/);
  assert.match(panel, /Consent returns to Platform; return here manually/);
  assert.match(panel, /at most 24 hours per run/);
  assert.match(panel, /Microsoft tenant\/subscriptions approved for this organization/);
  assert.match(app, /<SharedMicrosoftPilot provider="azure"/);
  assert.match(app, /<SharedMicrosoftPilot provider="entra"/);
  assert.doesNotMatch(panel, /client_secret|access_token|modal\.run|exec\(/);
});
