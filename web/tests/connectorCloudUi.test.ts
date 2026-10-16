import assert from "node:assert/strict";
import { after, afterEach, before, beforeEach, test } from "node:test";
import { fileURLToPath } from "node:url";
import { act, createElement, type ComponentType } from "react";
import { JSDOM } from "jsdom";
import { createServer, type ViteDevServer } from "vite";
import type { createRoot as CreateRoot, Root } from "react-dom/client";
import type { api } from "../src/api.ts";
import type { SharedConnectionAdapterProps } from "../src/sharedConnectionAdapter.ts";
import type { Connection } from "../src/types.ts";

type Provider = "aws" | "azure" | "entra" | "gcp";
type Props = SharedConnectionAdapterProps & { provider?: "azure" | "entra" };
const sources = {
  aws: { id: "aws-source", provider: "aws", connection_kind: "shared_aws", external_account_id: "123456789012", partition: "aws", coverage_mode: "selected", deployment_region: "us-east-1", regions: ["us-east-1"], availability: "ready", validated_scopes: ["aws.bedrock_agents", "aws.agentcore"], last_validated_at: null },
  azure: { id: "azure-source", provider: "azure", connection_kind: "shared_azure", display_name: "Approved Azure", tenant_id: "10000000-0000-0000-0000-000000000001", application_client_id: "20000000-0000-0000-0000-000000000001", subscriptions: [{ id: "30000000-0000-0000-0000-000000000001", name: "Production" }], availability: "ready", setup_state: "ready", health_state: "healthy", validated_scopes: ["azure.ai_services", "azure.ai_platform"] },
  entra: { id: "entra-source", provider: "entra", connection_kind: "shared_entra", display_name: "Approved Entra", tenant_id: "10000000-0000-0000-0000-000000000002", availability: "ready", setup_state: "ready", health_state: "healthy", validated_scopes: ["entra.ai_applications", "entra.permissions", "entra.sign_ins", "entra.directory_audits"] },
  gcp: { id: "gcp-source", provider: "gcp", connection_kind: "shared_gcp", display_name: "Approved Google Cloud", projects: [{ id: "approved-project", number: "123456789012" }], availability: "ready", validated_scopes: ["gcp.vertex_ai", "gcp.code_to_cloud"] },
};
const ready = { setup_state: "ready", job_state: null, health_state: "healthy", credential_state: "passed", job_error_code: null, validation_summary: "Current access verified", error_code: null, retry_available: false };
let dom: JSDOM;
let server: ViteDevServer;
let createRoot: typeof CreateRoot;
let root: Root;
let container: HTMLDivElement;
let panelApi: typeof api;
let originalApi: typeof api;
let panels: Record<Provider, ComponentType<Props>>;
let changed: number;
let attached: number;
const globals = new Map<string, PropertyDescriptor | undefined>();

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

before(async () => {
  dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://denali.test/connections" });
  for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document, navigator: dom.window.navigator, HTMLElement: dom.window.HTMLElement, IS_REACT_ACT_ENVIRONMENT: true })) {
    globals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
  ({ createRoot } = await import("react-dom/client"));
  server = await createServer({ root: fileURLToPath(new URL("../", import.meta.url)), configFile: false, envDir: false, appType: "custom", server: { middlewareMode: true, ws: false, watch: null }, optimizeDeps: { noDiscovery: true } });
  panelApi = (await server.ssrLoadModule("/src/api.ts")).api;
  originalApi = { ...panelApi };
  const aws = (await server.ssrLoadModule("/src/SharedAwsPilot.tsx")).SharedAwsPilot;
  const microsoft = (await server.ssrLoadModule("/src/SharedMicrosoftPilot.tsx")).SharedMicrosoftPilot;
  const gcp = (await server.ssrLoadModule("/src/SharedGcpPilot.tsx")).SharedGcpPilot;
  panels = { aws, azure: microsoft, entra: microsoft, gcp };
});

beforeEach(() => {
  changed = 0; attached = 0;
  Object.assign(panelApi, {
    sharedAwsConnections: async () => ({ items: [sources.aws] }),
    sharedAwsValidation: async () => ready,
    sharedMicrosoftConnections: async (provider: "azure" | "entra") => ({ items: [sources[provider]] }),
    sharedMicrosoftStatus: async () => ready,
    sharedGcpConnections: async () => ({ items: [sources.gcp] }),
    sharedGcpStatus: async () => ready,
  });
  container = document.createElement("div"); document.body.append(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove(); Object.assign(panelApi, originalApi);
});
after(async () => {
  await server.close(); dom.window.close();
  for (const [key, value] of globals) {
    if (value) Object.defineProperty(globalThis, key, value);
    else Reflect.deleteProperty(globalThis, key);
  }
});

async function mount(provider: Provider, overrides: Partial<Props> = {}) {
  await act(async () => root.render(createElement(panels[provider], {
    canWrite: true, onChanged: async () => { changed += 1; }, onAttached: () => { attached += 1; },
    ...(provider === "azure" || provider === "entra" ? { provider } : {}), ...overrides,
  })));
}
function button(text: string) {
  const found = [...container.querySelectorAll("button")].find((value) => value.textContent?.trim() === text);
  assert.ok(found, `Missing button ${text}`); return found;
}
async function click(element: HTMLElement) { await act(async () => { element.click(); }); }
async function select(value: string) {
  const element = container.querySelector("select"); assert.ok(element);
  await act(async () => { element.value = value; element.dispatchEvent(new dom.window.Event("change", { bubbles: true })); });
}
function setListing(provider: Provider, read: () => Promise<unknown>) {
  if (provider === "aws") Object.assign(panelApi, { sharedAwsConnections: read });
  else if (provider === "gcp") Object.assign(panelApi, { sharedGcpConnections: read });
  else Object.assign(panelApi, { sharedMicrosoftConnections: read });
}

for (const provider of ["aws", "azure", "entra", "gcp"] as const) {
  test(`${provider}: changed admission remains an explicit unavailable state with a read-only retry`, async () => {
    setListing(provider, () => Promise.reject(Object.assign(new Error("Not enabled"), { status: 404 })));
    await mount(provider);
    assert.match(container.textContent ?? "", /access is unavailable/);
    assert.match(container.textContent ?? "", /no native fallback was created/);
    assert.equal(container.querySelector("form"), null);
    setListing(provider, () => Promise.resolve({ items: [sources[provider]] }));
    await click(button("Check again"));
    assert.equal(button("Use in Denali").disabled, false);
  });

  test(`${provider}: initial loading is announced before any form or empty state`, async () => {
    const pending = deferred<{ items: [] }>(); setListing(provider, () => pending.promise);
    await mount(provider);
    assert.ok(container.querySelector('[aria-busy="true"] [role="status"]'));
    assert.equal(container.querySelector("form"), null);
    assert.doesNotMatch(container.textContent ?? "", /No reusable/);
    await act(async () => pending.resolve({ items: [] }));
    assert.ok(container.querySelector("form"));
    assert.match(container.textContent ?? "", /No reusable/);
    const checked = container.querySelectorAll('form input[type="checkbox"]:checked');
    assert.equal(checked.length, provider === "aws" ? 1 : provider === "gcp" ? 4 : provider === "azure" ? 5 : 0);
    if (provider === "entra") assert.match(container.textContent ?? "", /Directory.Read.All and AuditLog.Read.All/);
  });

  test(`${provider}: existing access is primary and new setup requires an explicit expansion`, async () => {
    await mount(provider);
    assert.equal(container.querySelector("form"), null);
    assert.equal(button("Use in Denali").disabled, false);
    const expander = container.querySelector<HTMLButtonElement>('.connector-access-expander'); assert.ok(expander);
    assert.equal(expander.getAttribute("aria-expanded"), "false");
    await click(expander);
    assert.ok(container.querySelector("form"));
    assert.equal(expander.getAttribute("aria-expanded"), "true");
    assert.equal(container.querySelector("select")?.value, sources[provider].id);
    if (provider === "azure") {
      assert.match(container.textContent ?? "", /Foundry runtime activity/);
      assert.equal(container.querySelectorAll("form .connector-choice").length, 5);
    }
  });

  test(`${provider}: a list failure has an explicit bounded retry and never reveals creation`, async () => {
    let attempts = 0;
    const retry = deferred<{ items: unknown[] }>();
    setListing(provider, () => { attempts += 1; return attempts === 1 ? Promise.reject(new Error("Temporary access outage")) : retry.promise; });
    await mount(provider);
    assert.match(container.querySelector('[role="alert"]')?.textContent ?? "", /Temporary access outage/);
    assert.equal(container.querySelector("form"), null);
    await click(button("Try again"));
    assert.equal(button("Retrying…").disabled, true);
    assert.ok(container.querySelector('[aria-busy="true"]'));
    assert.equal(attempts, 2);
    await act(async () => retry.resolve({ items: [sources[provider]] }));
    assert.equal(container.querySelector('[role="alert"]'), null);
    assert.equal(button("Use in Denali").disabled, false);
  });

  test(`${provider}: initial status blocks attachment and a failed status has read-only retry`, async () => {
    const pending = deferred<typeof ready>(); let reads = 0;
    const read = () => { reads += 1; return reads === 1 ? pending.promise : Promise.resolve(ready); };
    if (provider === "aws") Object.assign(panelApi, { sharedAwsValidation: read });
    else if (provider === "gcp") Object.assign(panelApi, { sharedGcpStatus: read });
    else Object.assign(panelApi, { sharedMicrosoftStatus: read });
    await mount(provider);
    assert.ok(container.querySelector('[aria-busy="true"]'));
    assert.equal(button("Use in Denali").disabled, true);
    await act(async () => pending.reject(new Error("Status temporarily unavailable")));
    assert.equal(button("Use in Denali").disabled, true);
    await click(button("Try again"));
    assert.equal(reads, 2);
    assert.equal(button("Use in Denali").disabled, false);
  });
}

test("Microsoft provider switches discard delayed Azure lists and reset the fixed Entra bundle", async () => {
  const old = deferred<{ items: unknown[] }>();
  Object.assign(panelApi, { sharedMicrosoftConnections: (provider: string) => provider === "azure" ? old.promise : Promise.resolve({ items: [] }) });
  await mount("azure"); await mount("entra");
  await act(async () => old.resolve({ items: [sources.azure] }));
  assert.doesNotMatch(container.textContent ?? "", /Approved Azure/);
  assert.match(container.textContent ?? "", /Fixed Microsoft Graph application bundle/);
  assert.equal(container.querySelectorAll('input[type="checkbox"]').length, 0);
});

test("a delayed Microsoft status cannot replace the current source or consent context", async () => {
  const old = deferred<typeof ready>();
  Object.assign(panelApi, {
    sharedMicrosoftConnections: async () => ({ items: [sources.azure, { ...sources.azure, id: "azure-second", display_name: "Second approved Azure" }] }),
    sharedMicrosoftStatus: async (_provider: string, id: string) => id === sources.azure.id ? old.promise : { ...ready, health_state: "Current second source" },
  });
  await mount("azure"); await select("azure-second");
  await act(async () => old.resolve({ ...ready, health_state: "STALE SOURCE" }));
  assert.match(container.textContent ?? "", /Current second source/);
  assert.doesNotMatch(container.textContent ?? "", /STALE SOURCE/);
});

test("an abandoned attachment never invokes callbacks in a replacement provider", async () => {
  const pending = deferred<Connection>();
  Object.assign(panelApi, { useSharedGcp: () => pending.promise });
  await mount("gcp"); await click(button("Use in Denali"));
  assert.ok(container.querySelector('[aria-busy="true"]'));
  await mount("azure");
  await act(async () => pending.resolve({ id: "old-organization-attachment" } as Connection));
  assert.equal(changed, 0); assert.equal(attached, 0);
  assert.doesNotMatch(container.textContent ?? "", /Attached in Denali/);
});

for (const provider of ["aws", "azure", "gcp"] as const) {
  test(`${provider}: attaching an existing connection preserves its saved evidence boundary`, async () => {
    const scope = provider === "aws" ? "aws.agentcore" : provider === "azure" ? "azure.ai_services" : "gcp.vertex_ai";
    const saved = {
      id: `saved-${provider}`, provider, declared_scopes: [scope],
      credential_reference: { type: `platform_shared_${provider}`, platform_connection_id: sources[provider].id },
      configuration: { coverage_mode: "selected", deployment_region: "us-east-1", regions: ["us-east-1"] },
    } as Connection;
    const calls: unknown[][] = [];
    if (provider === "aws") Object.assign(panelApi, { useSharedAwsConfiguration: async (id: string, body: { declared_scopes: string[] }) => { calls.push([id, body.declared_scopes]); return saved; } });
    else if (provider === "azure") Object.assign(panelApi, { useSharedMicrosoft: async (_provider: string, id: string, scopes: string[]) => { calls.push([id, scopes]); return saved; } });
    else Object.assign(panelApi, { useSharedGcp: async (id: string, scopes: string[]) => { calls.push([id, scopes]); return saved; } });
    await mount(provider, { connection: saved });
    assert.equal(container.querySelector("form"), null);
    assert.equal(container.querySelector("select")?.disabled, true);
    await click(button("Use in Denali"));
    assert.deepEqual(calls, [[sources[provider].id, [scope]]]);
    assert.equal(changed, 1); assert.equal(attached, 1);
  });

  test(`${provider}: a missing original source never selects a different reusable connection`, async () => {
    const saved = {
      id: `missing-${provider}`, provider, declared_scopes: [], configuration: {},
      credential_reference: { type: `platform_shared_${provider}`, platform_connection_id: "missing-original-source" },
    } as Connection;
    await mount(provider, { connection: saved });
    assert.match(container.textContent ?? "", /original .* connection is unavailable/);
    assert.equal(container.querySelector("form"), null);
    assert.equal([...container.querySelectorAll("button")].some((value) => value.textContent === "Use in Denali"), false);
  });
}

test("read-only members can inspect reusable access but cannot reveal a new-access form", async () => {
  for (const provider of ["aws", "azure", "entra", "gcp"] as const) {
    await mount(provider, { canWrite: false });
    assert.equal(container.querySelector("form"), null);
    assert.equal(container.querySelector(".connector-access-expander"), null);
    assert.equal([...container.querySelectorAll("button")].some((value) => value.textContent === "Use in Denali"), false);
  }
});
