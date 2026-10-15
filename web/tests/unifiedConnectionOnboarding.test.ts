import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createElement, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer, type ViteDevServer } from "vite";
import { connectionActionAvailable, connectionCoverageNotes, connectionJourney, connectionOnboardingPath } from "../src/connectionOnboarding.ts";
import type { ConnectionCatalogItem } from "../src/api.ts";
import type { Connection } from "../src/types.ts";
import type { ConnectionOnboardingWizard } from "../src/ConnectionOnboardingWizard.tsx";

const shared: ConnectionCatalogItem = {
  provider: "github", label: "GitHub", onboarding_path: "shared", shared_enabled: true,
  native_available: true, supported_scopes: ["github.repository_metadata"], parity_gaps: [], reason: null, reason_code: null,
};

test("onboarding uses the server path and never invents a native fallback", () => {
  assert.equal(connectionOnboardingPath(shared, false), "shared");
  assert.equal(connectionOnboardingPath(shared, true), "native");
  assert.equal(connectionOnboardingPath({ ...shared, native_available: false }, true), "shared");
  assert.equal(connectionOnboardingPath({ ...shared, shared_enabled: false }, false), "unavailable");
  assert.equal(connectionOnboardingPath(undefined, false), "unavailable");
  assert.equal(connectionOnboardingPath({ ...shared, onboarding_path: "native" }, false), "native");
});

test("healthy access does not complete the evidence collection stage", () => {
  const connection = { provider: "github", credential_reference: { type: "platform_shared_github" }, health_state: "healthy", last_source_collection: null } as Connection;
  assert.deepEqual(connectionJourney(connection).map((step) => step.state), ["complete", "complete", "current"]);
  assert.deepEqual(connectionJourney({ ...connection, last_source_collection: { state: "partial" } as Connection["last_source_collection"] }).map((step) => step.state), ["complete", "complete", "attention"]);
  assert.deepEqual(connectionJourney({ ...connection, last_source_collection: { state: "complete" } as Connection["last_source_collection"] }).map((step) => step.state), ["complete", "complete", "complete"]);
});

test("a newly created native plan still requires the provider grant", () => {
  const connection = { provider: "github", credential_reference: { type: "github_app_installation" }, health_state: "unknown", last_validation: null } as Connection;
  assert.deepEqual(connectionJourney(connection).map((step) => step.state), ["current", "pending", "pending"]);
  assert.deepEqual(connectionJourney(undefined, "verify").map((step) => step.state), ["complete", "current", "pending"]);
});

test("past healthy validation cannot authorize actions after shared access is unavailable", () => {
  const connection = { provider: "github", lifecycle_state: "active", credential_reference: { type: "platform_shared_github" }, health_state: "healthy", platform_availability: "disabled" } as Connection;
  assert.equal(connectionActionAvailable(connection, "validate"), false);
  assert.equal(connectionActionAvailable(connection, "collect"), false);
  assert.equal(connectionActionAvailable({ ...connection, platform_availability: "ready" }, "collect"), true);
  assert.equal(connectionActionAvailable({ ...connection, platform_availability: "ready", actions: { validate: false, collect: false } as Connection["actions"] }, "validate"), false);
});

test("capability limitations become customer-facing coverage notes, not rollout codes", () => {
  const notes = connectionCoverageNotes({ ...shared, parity_gaps: ["single_region_only", "additional_aws_planes_require_native", "hosted_acceptance_required"] });
  assert.deepEqual(notes, ["Reusable AWS access covers one selected Region.", "Additional AWS evidence planes use Denali setup."]);
});

let server: ViteDevServer;
let Wizard: ComponentType<Parameters<typeof ConnectionOnboardingWizard>[0]>;
before(async () => {
  server = await createServer({ root: fileURLToPath(new URL("../", import.meta.url)), configFile: false, envDir: false, appType: "custom", server: { middlewareMode: true, ws: false, watch: null }, optimizeDeps: { noDiscovery: true } });
  Wizard = (await server.ssrLoadModule("/src/ConnectionOnboardingWizard.tsx")).ConnectionOnboardingWizard;
});
after(async () => { await server?.close(); });

function render(overrides: Partial<Parameters<typeof ConnectionOnboardingWizard>[0]> = {}) {
  return renderToStaticMarkup(createElement(Wizard, {
    items: [shared], provider: "github", loading: false, error: null, nativeRequested: false, phase: "grant", managing: false,
    onProvider: () => {}, onNative: () => {}, onRetry: () => {}, onClose: () => {},
    children: createElement("p", null, "Selected GitHub adapter"), ...overrides,
  }));
}

test("one wizard renders provider choice and Grant, Verify, Collect with selected adapter", () => {
  const markup = render();
  assert.match(markup, /aria-label="Evidence source"/);
  assert.match(markup, /aria-pressed="true"[^>]*>GitHub/);
  for (const label of ["Grant access", "Verify access", "Collect evidence", "Selected GitHub adapter"]) assert.ok(markup.includes(label));
  assert.match(markup, /Reusable organization connection/);
});

test("catalog failure does not expose creation controls or the provider adapter", () => {
  const markup = render({ error: "Connection service is unavailable" });
  assert.match(markup, /role="alert"/);
  assert.match(markup, /Try again/);
  assert.doesNotMatch(markup, /Selected GitHub adapter|Evidence source|Use Denali setup/);
});

test("unsupported provider presents the server reason without rendering a creation adapter", () => {
  const markup = render({ items: [{ ...shared, onboarding_path: "unavailable", reason: "Contact an organization administrator" }] });
  assert.match(markup, /Contact an organization administrator/);
  assert.doesNotMatch(markup, /Selected GitHub adapter/);
});

test("managing an existing shared binding never offers switching it to native credentials", () => {
  const markup = render({ managing: true });
  assert.match(markup, /Review access and selected resources/);
  assert.doesNotMatch(markup, /Use Denali setup|Use reusable connection setup/);
});
