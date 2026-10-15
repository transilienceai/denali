import assert from "node:assert/strict";
import { after, afterEach, before, beforeEach, test } from "node:test";
import { fileURLToPath } from "node:url";
import { act, createElement, useState, type ComponentType } from "react";
import { JSDOM } from "jsdom";
import { createServer, type ViteDevServer } from "vite";
import type { createRoot as createRootType, Root } from "react-dom/client";
import type { api, ConnectionCatalog, SharedAzureReposConnection } from "../src/api.ts";
import type { ConnectionsPage } from "../src/App.tsx";
import type { Connection } from "../src/types.ts";

const repository = (id: number) => ({ id, node_id: `node-${id}`, name: `repo-${id}`, full_name: `fixture/repo-${id}`, owner_id: 1, owner_login: "fixture", private: true, archived: false, default_branch: "main" });
const repositories = [repository(41), repository(42), repository(43)];
const installation = { id: "shared-installation", provider: "github" as const, connection_kind: "shared_github" as const, account_id: 1, account_login: "fixture", installation_id: 10, repository_selection: "all" as const, repository_count: 3, availability: "ready" as const, validated_scopes: ["github.repository_metadata"], last_validated_at: "2026-10-15T10:00:00Z" };
const attached: Connection = {
  id: "selected-connection", provider: "github", display_name: "Selected GitHub repositories", lifecycle_state: "active", health_state: "unknown",
  credential_reference: { type: "platform_shared_github", platform_connection_id: installation.id, installation_id: 10 },
  declared_scopes: ["github.repository_metadata"], coverage_plan: [], configuration: { account_login: "fixture", repositories: [repositories[1]] },
  setup_capabilities: { cloudformation_quick_create: false, azure_cloud_shell: false, gcp_cloud_shell: false, github_app: false, azure_repos_oauth: false, entra_admin_consent: false, google_workspace_admin_authorization: false },
  created_at: "2026-10-15T10:00:00Z", updated_at: "2026-10-15T10:00:00Z", last_validated_at: null, last_validation: null,
};
const azureRepository = (value: number) => ({ id: `00000000-0000-0000-0000-${String(value).padStart(12, "0")}`, project_id: "10000000-0000-0000-0000-000000000001", name: `repo-${value}`, project_name: "Fixture", full_name: `Fixture/repo-${value}`, default_branch: "refs/heads/main" });
const azureRepositories = [azureRepository(41), azureRepository(42), azureRepository(43)];
const azureSource: SharedAzureReposConnection = {
  id: "20000000-0000-0000-0000-000000000001", provider: "azure_repos", connection_kind: "shared_azure_repos",
  target_id: "30000000-0000-0000-0000-000000000001", tenant_id: "40000000-0000-0000-0000-000000000001",
  application_client_id: "50000000-0000-0000-0000-000000000001", organization: "fixture", display_name: "Fixture Azure Repos",
  lifecycle_state: "active", setup_state: "ready", health_state: "healthy", availability: "ready", repository_count: 3,
  declared_scopes: ["azure_repos.repository_metadata", "azure_repos.repository_contents"],
  validated_scopes: ["azure_repos.repository_metadata", "azure_repos.repository_contents"],
  authority_revision: 1, last_validated_at: "2026-10-15T10:00:00Z",
};
const azureAttached: Connection = {
  ...attached, id: "azure-selected-connection", provider: "azure_repos", display_name: "Selected Azure repositories",
  credential_reference: { type: "platform_shared_azure_repos", platform_connection_id: azureSource.id },
  declared_scopes: [...azureSource.declared_scopes],
  configuration: { tenant_id: azureSource.tenant_id, organization: azureSource.organization, repositories: azureRepositories.slice(0, 2) },
};
const catalog: ConnectionCatalog = {
  items: ["github", "gcp", "aws", "azure_repos"].map((provider) => ({ provider: provider as Connection["provider"], label: provider === "github" ? "GitHub" : provider === "gcp" ? "Google Cloud" : provider === "azure_repos" ? "Azure Repos" : "Amazon Web Services", onboarding_path: "shared", shared_enabled: true, native_available: true, supported_scopes: [], parity_gaps: [], reason: null, reason_code: null })),
  platform_only: false, platform_only_blockers: [],
};

let dom: JSDOM;
let server: ViteDevServer;
let Page: ComponentType<Parameters<typeof ConnectionsPage>[0]>;
let pageApi: typeof api;
let originalApi: typeof api;
let createRoot: typeof createRootType;
let root: Root;
let container: HTMLDivElement;
let calls: { github: number; gcp: number; aws: number; azure: number; native: number; disable: number; localDisable: string[]; attaches: Array<{ id: string; ids?: number[]; scopes?: string[] }>; azureAttaches: Array<{ id: string; ids: string[]; scopes: string[] }> };
let nextAttachment: Connection;
let acceptedOperations: Array<{ id: string; kind: string }>;
const originalGlobals = new Map<string, PropertyDescriptor | undefined>();

before(async () => {
  dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://denali.test/connections" });
  for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document, navigator: dom.window.navigator, HTMLElement: dom.window.HTMLElement, IS_REACT_ACT_ENVIRONMENT: true })) {
    originalGlobals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
  ({ createRoot } = await import("react-dom/client"));
  server = await createServer({ root: fileURLToPath(new URL("../", import.meta.url)), configFile: false, envDir: false, appType: "custom", server: { middlewareMode: true, ws: false, watch: null }, optimizeDeps: { noDiscovery: true } });
  Page = (await server.ssrLoadModule("/src/App.tsx")).ConnectionsPage;
  pageApi = (await server.ssrLoadModule("/src/api.ts")).api;
  originalApi = { ...pageApi };
});
beforeEach(() => {
  calls = { github: 0, gcp: 0, aws: 0, azure: 0, native: 0, disable: 0, localDisable: [], attaches: [], azureAttaches: [] };
  nextAttachment = attached;
  acceptedOperations = [];
  dom.window.confirm = () => true;
  Object.assign(pageApi, {
    connectionCatalog: async () => catalog,
    sharedGithubConnections: async () => { calls.github += 1; return { items: [installation] }; },
    sharedGithubRepositories: async () => ({ items: repositories }),
    sharedGcpConnections: async () => { calls.gcp += 1; return { items: [] }; },
    sharedAwsConnections: async () => { calls.aws += 1; return { items: [] }; },
    sharedAzureReposConfig: async () => ({ items: [azureSource] }),
    sharedAzureReposConnections: async () => { calls.azure += 1; return { items: [azureSource] }; },
    sharedAzureReposStatus: async () => azureSource,
    sharedAzureReposRepositories: async () => ({ items: azureRepositories }),
    useSharedAzureRepos: async (id: string, ids: string[], scopes: string[]) => { calls.azureAttaches.push({ id, ids, scopes }); nextAttachment = azureAttached; return azureAttached; },
    useSharedGithubInDenali: async (id: string, ids?: number[], scopes?: string[]) => { calls.attaches.push({ id, ids, scopes }); return attached; },
    createConnection: async () => { calls.native += 1; return attached; },
    disableSharedGithub: async () => { calls.disable += 1; return { status: "disabled" }; },
    disableSharedAzureRepos: async () => { calls.disable += 1; return { status: "disabled" }; },
    disableSharedAws: async () => { calls.disable += 1; return { status: "disabled" }; },
    disableConnection: async (id: string) => { calls.localDisable.push(id); return { ...azureAttached, lifecycle_state: "disabled" }; },
  });
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  Object.assign(pageApi, originalApi);
});
after(async () => {
  await server?.close();
  dom?.window.close();
  for (const [key, descriptor] of originalGlobals) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
});

function Harness({ initialConnections = [], initialQuery = { new: "1", provider: "github" }, canWrite = true }: { initialConnections?: Connection[]; initialQuery?: Record<string, string>; canWrite?: boolean }) {
  const [rows, setRows] = useState(initialConnections);
  const [query, setQuery] = useState(initialQuery);
  const update = (values: Record<string, string | null | undefined>) => setQuery((previous) => {
    const next = { ...previous };
    for (const [key, value] of Object.entries(values)) {
      if (value) next[key] = value;
      else delete next[key];
    }
    return next;
  });
  return createElement(Page, {
    connections: rows, selectedId: query.connection, showCreate: query.new === "1" || Boolean(query.onboarding), canWrite,
    navigation: { values: query, set: (key, value, defaultValue = "") => update({ [key]: value === defaultValue ? null : value }), clear: (keys) => update(Object.fromEntries(keys.map((key) => [key, null]))), update },
    onSelect: (id) => setQuery(id ? { connection: id } : {}),
    onShowCreate: (visible) => update({ new: visible ? "1" : null, manage: null, onboarding: null }),
    onChanged: async () => { setRows([...initialConnections.filter((row) => row.id !== nextAttachment.id), nextAttachment]); }, onOperationAccepted: (id, kind) => { acceptedOperations.push({ id, kind }); },
    entraSetupReturn: null, githubSetupReturn: null, azureReposSetupReturn: null,
  });
}

async function mount(props: Parameters<typeof Harness>[0] = {}) {
  await act(async () => { root.render(createElement(Harness, props)); });
}
function button(label: string) {
  const match = [...container.querySelectorAll("button")].find((element) => element.textContent?.trim() === label);
  assert.ok(match, `Missing button: ${label}`);
  return match;
}
async function click(element: HTMLElement) {
  await act(async () => { element.click(); });
}
async function select(element: HTMLSelectElement, value: string) {
  await act(async () => { element.value = value; element.dispatchEvent(new dom.window.Event("change", { bubbles: true })); });
}
function repositoryCheckboxes() {
  return [...container.querySelectorAll<HTMLInputElement>('.shared-github-repository-choice input[type="checkbox"]')]
    .filter((input) => !input.closest('[aria-label="GitHub evidence selection"]') && !input.closest("form"));
}

test("changing provider mounts only that provider's adapter inside the single wizard", async () => {
  await mount();
  assert.equal(calls.github, 1);
  assert.equal(calls.gcp, 0);
  assert.equal(calls.aws, 0);
  assert.equal(container.querySelectorAll('[aria-label="Connect an evidence source"]').length, 1);
  await click(button("Google Cloud"));
  assert.equal(calls.gcp, 1);
  assert.equal(calls.aws, 0);
  assert.equal(container.querySelector('[aria-label="GitHub access and repository selection"]'), null);
  assert.ok(container.querySelector('[aria-label="Shared Google Cloud onboarding"]'));
});

test("selecting repositories attaches exactly that set and opens the returned local connection", async () => {
  await mount();
  const checkboxes = repositoryCheckboxes();
  assert.equal(checkboxes.length, 3);
  assert.ok([...checkboxes].every((checkbox) => !checkbox.checked));
  await click(checkboxes[1]);
  await click(button("Use selected repositories in Denali"));
  assert.deepEqual(calls.attaches, [{ id: installation.id, ids: [42], scopes: ["github.repository_metadata"] }]);
  assert.equal(container.querySelector('[aria-label="Connect an evidence source"]'), null);
  assert.match(container.querySelector(".connection-list button.active")?.textContent ?? "", /Selected GitHub repositories/);
  assert.equal(calls.native, 0);
  assert.equal(calls.disable, 0);
});

test("managing a saved selection retains its two repositories and leaves additions unchecked", async () => {
  const existing = { ...attached, id: "existing-connection", display_name: "Existing selection", configuration: { account_login: "fixture", repositories: repositories.slice(0, 2) } };
  await mount({ initialConnections: [existing], initialQuery: { new: "1", provider: "github", manage: existing.id } });
  let checkboxes = repositoryCheckboxes();
  assert.deepEqual([...checkboxes].map((checkbox) => checkbox.checked), [true, true, false]);
  await click(button("Reload saved access"));
  checkboxes = repositoryCheckboxes();
  assert.deepEqual([...checkboxes].map((checkbox) => checkbox.checked), [true, true, false]);
  assert.match(container.textContent ?? "", /2 saved · 2 in this review/);
  await click(checkboxes[2]);
  await click(button("Save reviewed repository selection"));
  assert.deepEqual(calls.attaches, [{ id: installation.id, ids: [41, 42, 43], scopes: existing.declared_scopes }]);
  assert.equal(container.querySelectorAll(".connection-list button").length, 2);
  assert.equal(existing.configuration.repositories.length, 2);
  assert.equal(calls.disable, 0);
});

test("reviewing GitHub repositories never silently adds newly granted evidence scopes", async () => {
  let source = installation;
  pageApi.sharedGithubConnections = async () => ({ items: [source] });
  await mount({ initialConnections: [attached], initialQuery: { new: "1", provider: "github", manage: attached.id } });
  source = { ...installation, validated_scopes: ["github.repository_metadata", "github.repository_contents", "github.actions_workflows"] };
  await click(button("Reload saved access"));
  const scopeCheckboxes = [...container.querySelectorAll<HTMLInputElement>('[aria-label="GitHub evidence selection"] input[type="checkbox"]')];
  assert.equal(scopeCheckboxes.length, 3);
  assert.deepEqual(scopeCheckboxes.map((input) => input.checked), [true, false, false]);
  await click(repositoryCheckboxes()[2]);
  await click(button("Save reviewed repository selection"));
  assert.deepEqual(calls.attaches, [{ id: installation.id, ids: [42, 43], scopes: ["github.repository_metadata"] }]);
  assert.deepEqual(attached.declared_scopes, ["github.repository_metadata"]);
});

test("managing disabled GitHub access starts an exact reverify without reattaching or reactivating Denali", async () => {
  const existing: Connection = { ...attached, lifecycle_state: "disabled" };
  const setupRequests: Array<NonNullable<Parameters<typeof api.startSharedGithubSetup>[0]>> = [];
  pageApi.sharedGithubConnections = async () => ({ items: [{ ...installation, availability: "disabled" as const }] });
  pageApi.startSharedGithubSetup = async (input) => {
    setupRequests.push(input!);
    return { install_url: "https://invalid.example/setup" };
  };
  await mount({ initialConnections: [existing], initialQuery: { new: "1", provider: "github", manage: existing.id } });
  await click(button("Manage repository access in GitHub"));
  assert.equal(setupRequests.length, 1);
  assert.equal(setupRequests[0]?.connection_id, existing.id);
  assert.equal(setupRequests[0]?.platform_connection_id, installation.id);
  assert.match(setupRequests[0]?.request_id ?? "", /^[a-f0-9-]{36}$/);
  assert.match(container.querySelector('[role="alert"]')?.textContent ?? "", /setup link is invalid/);
  assert.equal(calls.attaches.length, 0);
  assert.equal(calls.native, 0);
  assert.equal(calls.disable, 0);
  assert.equal(existing.lifecycle_state, "disabled");
  assert.match(container.textContent ?? "", /Reviewing GitHub access does not reactivate it/);
});

test("a shared upstream error remains visible without creating or selecting a native fallback", async () => {
  pageApi.sharedGithubConnections = async () => { throw new Error("Organization access is temporarily unavailable"); };
  await mount();
  assert.match(container.querySelector('[role="alert"]')?.textContent ?? "", /temporarily unavailable/);
  assert.equal(container.querySelector("form.connection-create"), null);
  assert.equal(calls.native, 0);
  assert.equal(calls.attaches.length, 0);
});

test("read-only members cannot open connector creation or manage shared access", async () => {
  await mount({ initialConnections: [attached], initialQuery: {}, canWrite: false });
  assert.equal(container.querySelector('[aria-label="Connect an evidence source"]'), null);
  assert.ok(![...container.querySelectorAll("button")].some((element) => /Add connection|Manage access and selected resources/.test(element.textContent ?? "")));
  assert.equal(calls.github, 0);
  assert.equal(calls.native, 0);
});

test("Azure Repos preserves saved exact identities and leaves available additions unchecked", async () => {
  await mount({ initialConnections: [azureAttached], initialQuery: { new: "1", provider: "azure_repos", manage: azureAttached.id } });
  const checkboxes = repositoryCheckboxes();
  assert.deepEqual([...checkboxes].map((checkbox) => checkbox.checked), [true, true, false]);
  assert.match(container.textContent ?? "", /Available: 3 verified repositories/);
  await click(checkboxes[2]);
  await click(button("Use selected repositories in Denali"));
  assert.deepEqual(calls.azureAttaches, [{ id: azureSource.id, ids: azureRepositories.map((repo) => repo.id), scopes: azureSource.declared_scopes }]);
  assert.equal(container.querySelector('[aria-label="Connect an evidence source"]'), null);
  assert.equal(azureAttached.configuration.repositories?.length, 2);
  assert.equal(calls.native, 0);
  assert.equal(calls.disable, 0);
});

test("Azure Repos can prepare a metadata-only plan without implicitly requesting source access", async () => {
  const created: Array<{ target_id: string; request_id: string; declared_scopes: string[] }> = [];
  pageApi.sharedAzureReposConnections = async () => ({ items: [] });
  pageApi.createSharedAzureRepos = async (input) => { created.push(input); return { id: azureSource.id }; };
  await mount({ initialQuery: { new: "1", provider: "azure_repos" } });
  const form = container.querySelector("form.shared-aws-pilot-form");
  assert.ok(form);
  const checkboxes = form.querySelectorAll<HTMLInputElement>('input[type="checkbox"]');
  assert.equal(checkboxes.length, 2);
  assert.ok(checkboxes[0].checked);
  if (checkboxes[1].checked) await click(checkboxes[1]);
  await click(button("Prepare Azure Repos connection"));
  assert.equal(created.length, 1);
  assert.equal(created[0].target_id, azureSource.target_id);
  assert.match(created[0].request_id, /^[0-9a-f-]{36}$/);
  assert.deepEqual(created[0].declared_scopes, ["azure_repos.repository_metadata"]);
  assert.equal(calls.native, 0);
});

test("Azure Repos refreshes reauthorized repository candidates without expanding saved selection", async () => {
  let source = { ...azureSource, repository_count: 2 };
  let available = azureRepositories.slice(0, 2);
  pageApi.sharedAzureReposConnections = async () => ({ items: [source] });
  pageApi.sharedAzureReposStatus = async () => source;
  pageApi.sharedAzureReposRepositories = async () => ({ items: available });
  await mount({ initialConnections: [azureAttached], initialQuery: { new: "1", provider: "azure_repos", manage: azureAttached.id } });
  assert.deepEqual([...repositoryCheckboxes()].map((checkbox) => checkbox.checked), [true, true]);
  source = { ...source, repository_count: 3, authority_revision: 2 };
  available = azureRepositories;
  await click(button("Check status"));
  assert.deepEqual([...repositoryCheckboxes()].map((checkbox) => checkbox.checked), [true, true, false]);
  assert.equal(calls.azureAttaches.length, 0);
});

test("an unavailable original Azure Repos plan never falls back to another organization plan", async () => {
  pageApi.sharedAzureReposConnections = async () => ({ items: [{ ...azureSource, id: "20000000-0000-0000-0000-000000000099" }] });
  await mount({ initialConnections: [azureAttached], initialQuery: { new: "1", provider: "azure_repos", manage: azureAttached.id } });
  assert.match(container.querySelector('[role="alert"]')?.textContent ?? "", /original Azure Repos plan is unavailable/);
  assert.equal(container.querySelector('[aria-label="Azure Repos access and repository selection"] select'), null);
  assert.ok(![...container.querySelectorAll("button")].some((element) => element.textContent === "Use selected repositories in Denali"));
  assert.equal(calls.azureAttaches.length, 0);
});

test("a setup return from another active organization blocks all provider controls", async () => {
  pageApi.onboardingWorkflow = async () => { throw new Error("This setup belongs to another organization"); };
  await mount({ initialQuery: { onboarding: "60000000-0000-0000-0000-000000000001", provider: "azure_repos" } });
  assert.match(container.querySelector('[role="alert"]')?.textContent ?? "", /another organization/);
  assert.equal(container.querySelector('[aria-label="Azure Repos access and repository selection"]'), null);
  assert.equal(calls.azure, 0);
  assert.equal(calls.native, 0);
});

test("disconnecting a shared Azure Repos attachment affects only its local Denali connection", async () => {
  await mount({ initialConnections: [azureAttached], initialQuery: { connection: azureAttached.id } });
  await click(button("Disconnect from Denali"));
  assert.deepEqual(calls.localDisable, [azureAttached.id]);
  assert.equal(calls.disable, 0);
  assert.equal(calls.azure, 0);
  assert.match(container.textContent ?? "", /Previously collected evidence remains/);
});

test("the shared AWS exact-resource option stays hidden without server catalog admission", async () => {
  pageApi.connectionCatalog = async () => ({ ...catalog, items: catalog.items.map((item) => item.provider === "aws" ? { ...item, supported_coverage_modes: ["selected", "automatic"] } : item) });
  await mount({ initialQuery: { new: "1", provider: "aws" } });
  assert.ok(container.querySelector('[aria-label="Shared AWS onboarding"]'));
  assert.equal(container.querySelector('option[value="selected-resource"]'), null);
  assert.equal(container.querySelector('select option:checked')?.getAttribute("value"), "aws");
  assert.deepEqual([...container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')].map((input) => input.checked), [true, false, false, false, false, false]);
});

test("the admitted AWS exact-resource option reveals exact pins and removes discovery scopes", async () => {
  pageApi.connectionCatalog = async () => ({ ...catalog, items: catalog.items.map((item) => item.provider === "aws" ? { ...item, supported_coverage_modes: ["selected", "automatic", "selected-resource"] } : item) });
  await mount({ initialQuery: { new: "1", provider: "aws" } });
  const exact = container.querySelector<HTMLOptionElement>('option[value="selected-resource"]');
  assert.ok(exact);
  const coverage = exact.parentElement;
  assert.ok(coverage instanceof dom.window.HTMLSelectElement);
  await select(coverage as HTMLSelectElement, "selected-resource");
  assert.match(container.textContent ?? "", /No account discovery, source download, invocation, or account-wide health claim/);
  assert.equal(container.querySelectorAll('input[type="checkbox"]').length, 0);
  assert.equal(container.querySelectorAll('input[maxlength="300"]').length, 3);
  assert.equal(calls.native, 0);
});

function runtimeConnection(provider: "aws" | "azure", shared = true): Connection {
  return {
    ...attached, id: `${provider}-runtime`, provider, display_name: `${provider} runtime`, health_state: "healthy",
    declared_scopes: [`${provider}.agent_runtime_activity`],
    credential_reference: shared
      ? { type: provider === "aws" ? "platform_shared_aws" : "platform_shared_azure", platform_connection_id: `${provider}-shared` }
      : provider === "aws" ? { type: "aws_assume_role", role_arn: "arn:aws:iam::123456789012:role/Reader" }
        : { type: "azure_multitenant_app", client_id: "10000000-0000-0000-0000-000000000001" },
    configuration: { account_id: "123456789012", regions: ["us-east-1"], subscriptions: [{ id: "10000000-0000-0000-0000-000000000002", name: "Fixture" }] },
    validation_state: "idle", deployment_collection_state: "idle", runtime_collection_state: "idle",
    last_deployment_collection: null, last_runtime_collection: null,
  };
}

for (const provider of ["aws", "azure"] as const) {
  for (const shared of [true, false]) {
    test(`${provider} ${shared ? "shared" : "native"}: a reloaded runtime job shows Collecting and a later failed result needs attention`, async () => {
      const running = { ...runtimeConnection(provider, shared), runtime_collection_state: "running" as const };
      await mount({ initialConnections: [running], initialQuery: { connection: running.id } });
      const badges = [...container.querySelectorAll(".connection-health")];
      assert.ok(badges.length > 0);
      assert.ok(badges.every((badge) => badge.textContent === "Collecting"));
      assert.match(container.querySelector('[role="status"]')?.textContent ?? "", /evidence is being collected/);
      assert.equal(container.querySelector('[aria-label="Connection progress"] li:last-child')?.className, "current");

      const failed = { ...running, runtime_collection_state: "idle" as const, last_runtime_collection: { state: "failed" as const, completed_at: "2026-10-16T00:01:00Z" } };
      // Recreate the page to model leaving and returning with a durable terminal result.
      await act(async () => root.render(createElement(Harness, { key: "returned", initialConnections: [failed], initialQuery: { connection: failed.id } })));
      assert.ok([...container.querySelectorAll(".connection-health")].every((badge) => badge.textContent === "Needs attention"));
      assert.equal(container.querySelector('[aria-label="Connection progress"] li:last-child')?.className, "attention");
    });
  }

  test(`${provider}: accepting runtime-only collection marks runtime and waits for its actual result`, async () => {
    const previous = runtimeConnection(provider);
    const running = { ...previous, runtime_collection_state: "running" as const };
    const done = { ...previous, last_runtime_collection: { state: "complete" as const, completed_at: "2026-10-16T00:01:00Z" } };
    const states = [running, done];
    let reads = 0;
    pageApi.collectAzureDeployments = async () => ({ status: "started", connection_id: previous.id });
    pageApi.collectAwsDeployments = async () => ({ status: "started", connection_id: previous.id });
    pageApi.connection = async () => { reads += 1; nextAttachment = done; return states.shift()!; };
    const originalTimeout = dom.window.setTimeout;
    dom.window.setTimeout = ((handler: TimerHandler, timeout?: number) => {
      if (timeout === 2000 && typeof handler === "function") { queueMicrotask(() => handler()); return 0; }
      return originalTimeout.call(dom.window, handler, timeout);
    }) as typeof dom.window.setTimeout;
    try {
      await mount({ initialConnections: [previous], initialQuery: { connection: previous.id } });
      await click(button(provider === "aws" ? "Collect AWS evidence" : "Collect Microsoft evidence"));
      assert.equal(reads, 2);
      assert.deepEqual(acceptedOperations, [{ id: previous.id, kind: "runtime" }]);
      assert.match(container.textContent ?? "", new RegExp(`${provider === "aws" ? "AWS" : "Azure"} evidence collection completed\\.`));
      assert.ok([...container.querySelectorAll(".connection-health")].every((badge) => badge.textContent === "Ready"));
      assert.equal(container.querySelector('[aria-label="Connection progress"] li:last-child')?.className, "complete");
    } finally {
      dom.window.setTimeout = originalTimeout;
    }
  });

  test(`${provider}: shared detail exposes validation proof and every selected collection outcome`, async () => {
    const completedAt = "2026-10-16T00:01:00Z";
    const row: Connection = {
      ...runtimeConnection(provider), declared_scopes: [`${provider}.agent_runtime_activity`, provider === "aws" ? "aws.bedrock" : "azure.ai_services"],
      last_validation: {
        started_at: "2026-10-16T00:00:00Z", completed_at: completedAt, health_state: "healthy", credential_state: "passed", account_id_observed: "fixture-identity",
        summary: "Selected access verified", results: [{ scope: "fixture-scope", plane: "runtime", label: "Runtime read proof", region: "fixture-region", state: "passed", detail: "Declared read-only runtime access responded" }],
      },
      last_deployment_collection: provider === "aws"
        ? { connection_id: "aws-runtime", state: "complete", completed_at: completedAt, region_count: 1, partial_count: 0, failed_count: 0, regions: [] }
        : { connection_id: "azure-runtime", state: "complete", completed_at: completedAt, subscription_count: 1, partial_count: 0, failed_count: 0, subscriptions: [] },
      last_runtime_collection: { state: "partial", completed_at: completedAt, activities: 4, detail: "One runtime boundary was unavailable", partial_regions: 1 },
    };
    await mount({ initialConnections: [row], initialQuery: { connection: row.id } });
    const validation = container.querySelector('[aria-label="Connection validation results"]');
    assert.match(validation?.textContent ?? "", /Selected access verified/);
    assert.match(validation?.textContent ?? "", /Runtime read proof/);
    assert.match(validation?.textContent ?? "", /Declared read-only runtime access responded/);
    assert.equal(validation?.querySelector("time")?.dateTime, completedAt);
    const collections = container.querySelector('[aria-label="Connection collection results"]');
    assert.equal(collections?.querySelectorAll("section").length, 2);
    assert.match(collections?.textContent ?? "", /Deployment evidence/);
    assert.match(collections?.textContent ?? "", /Latest result: Complete/);
    assert.match(collections?.textContent ?? "", /Latest result: Partial/);
    assert.match(collections?.textContent ?? "", /4 activity events/);
    assert.match(collections?.textContent ?? "", /One runtime boundary was unavailable/);
    assert.deepEqual([...collections!.querySelectorAll("time")].map((time) => time.dateTime), [completedAt, completedAt]);
    assert.ok([...container.querySelectorAll(".connection-health")].every((badge) => badge.textContent === "Needs attention"));
  });
}

test("shared Microsoft Entra shows its audit outcome without inventing deployment or runtime coverage", async () => {
  const row: Connection = {
    ...runtimeConnection("azure"), id: "entra-audit", provider: "entra", credential_reference: { type: "platform_shared_entra", platform_connection_id: "shared-entra" },
    declared_scopes: ["entra.enterprise_applications"], last_evidence_collection: { state: "complete", completed_at: "2026-10-16T00:01:00Z", activity_events: 5, coverage_complete: 2, detail: "Bounded audit metadata collected" },
  };
  await mount({ initialConnections: [row], initialQuery: { connection: row.id } });
  const results = container.querySelector('[aria-label="Connection collection results"]');
  assert.equal(results?.querySelectorAll("section").length, 1);
  assert.match(results?.textContent ?? "", /Audit evidence/);
  assert.match(results?.textContent ?? "", /5 activity events/);
  assert.match(results?.textContent ?? "", /Bounded audit metadata collected/);
  assert.doesNotMatch(results?.textContent ?? "", /Deployment evidence|runtime activity/);
});

test("shared runtime detail labels an older result while a new collection runs", async () => {
  const row: Connection = { ...runtimeConnection("azure"), runtime_collection_state: "running", last_runtime_collection: { state: "complete", completed_at: "2026-10-16T00:01:00Z" } };
  await mount({ initialConnections: [row], initialQuery: { connection: row.id } });
  const results = container.querySelector('[aria-label="Connection collection results"]');
  assert.match(results?.textContent ?? "", /Collection in progress. The result below is from the previous run/);
  assert.equal(results?.querySelectorAll("section").length, 1);
  assert.ok([...container.querySelectorAll(".connection-health")].every((badge) => badge.textContent === "Collecting"));
});

test("shared exact AWS result never implies Region discovery or account inventory", async () => {
  const row: Connection = {
    ...runtimeConnection("aws"), health_state: "partial", declared_scopes: ["aws.code_to_cloud"], configuration: { coverage_mode: "selected-resource" },
    last_deployment_collection: { connection_id: "aws-runtime", state: "complete", completed_at: "2026-10-16T00:01:00Z", region_count: 0, partial_count: 0, failed_count: 0, regions: [], resource_coverage_state: "complete", account_coverage: "not_assessed" },
  };
  await mount({ initialConnections: [row], initialQuery: { connection: row.id } });
  const results = container.querySelector('[aria-label="Connection collection results"]');
  assert.match(results?.textContent ?? "", /Selected-resource evidence/);
  assert.match(results?.textContent ?? "", /Account inventory: not assessed/);
  assert.doesNotMatch(results?.textContent ?? "", /0 Regions/);
  assert.ok([...container.querySelectorAll(".connection-health")].every((badge) => badge.textContent === "Partial"));
});

for (const shared of [true, false]) {
  for (const state of ["complete", "partial", "failed"] as const) {
    test(`Azure Repos ${shared ? "shared" : "native"}: terminal ${state} source result and finish time remain inspectable`, async () => {
      const completedAt = "2026-10-16T00:02:00Z";
      const row: Connection = {
        ...azureAttached, health_state: "healthy", source_collection_state: "idle",
        credential_reference: shared ? azureAttached.credential_reference : { type: "azure_repos_service_principal", client_id: azureSource.application_client_id },
        last_validation: {
          started_at: "2026-10-16T00:00:00Z", completed_at: "2026-10-16T00:01:00Z", health_state: "healthy", credential_state: "passed", account_id_observed: "fixture",
          summary: "Exact repository metadata verified", results: [{ scope: "azure_repos.repository_metadata", plane: "repository_metadata", label: "Repository metadata", region: "global", state: "passed", detail: "Saved project and repository identities matched", repository_id: azureRepositories[0]!.id, repository_full_name: azureRepositories[0]!.full_name }],
        },
        last_source_collection: { connection_id: azureAttached.id, state, completed_at: completedAt, repository_count: 2, failed_count: state === "failed" ? 2 : 0, partial_count: state === "partial" ? 1 : 0, repositories: [], detail: `Recorded ${state} source analysis outcome` },
      };
      await mount({ initialConnections: [row], initialQuery: { connection: row.id } });
      const results = container.querySelector('[aria-label="Connection collection results"]');
      assert.equal(results?.querySelectorAll("section").length, 1);
      assert.match(results?.textContent ?? "", /Repository source evidence/);
      assert.match(results?.textContent ?? "", new RegExp(`Latest result: ${state[0]!.toUpperCase()}${state.slice(1)}`));
      assert.match(results?.textContent ?? "", /2 repositories/);
      assert.match(results?.textContent ?? "", new RegExp(`Recorded ${state} source analysis outcome`));
      assert.equal(results?.querySelector("time")?.dateTime, completedAt);
      if (shared) {
        const validation = container.querySelector('[aria-label="Connection validation results"]');
        assert.match(validation?.textContent ?? "", /Exact repository metadata verified/);
        assert.match(validation?.textContent ?? "", /Saved project and repository identities matched/);
      }
      assert.ok([...container.querySelectorAll(".connection-health")].every((badge) => badge.textContent === (state === "complete" ? "Ready" : "Needs attention")));
      assert.equal(calls.azure, 0);
      assert.equal(calls.native, 0);
    });
  }
}

test("shared GCP shows validation proof and the recorded partial project collection outcome", async () => {
  const completedAt = "2026-10-16T00:02:00Z";
  const row: Connection = {
    ...attached, id: "gcp-shared-result", provider: "gcp", health_state: "healthy", declared_scopes: ["gcp.ai_services"],
    credential_reference: { type: "platform_shared_gcp", platform_connection_id: "gcp-shared" }, configuration: { projects: [{ id: "fixture-project", number: "123456789012", name: "Fixture" }] },
    last_validation: {
      started_at: "2026-10-16T00:00:00Z", completed_at: "2026-10-16T00:01:00Z", health_state: "healthy", credential_state: "passed", account_id_observed: "fixture-project",
      summary: "Selected project access verified", results: [{ scope: "gcp.ai_services", plane: "ai_services", label: "AI service metadata", region: "global", state: "passed", detail: "Selected project read returned", project_id: "fixture-project", project_name: "Fixture" }],
    },
    last_deployment_collection: { connection_id: "gcp-shared-result", state: "partial", completed_at: completedAt, project_count: 1, failed_count: 0, partial_count: 1, projects: [], detail: "Project collection has incomplete coverage" },
  };
  await mount({ initialConnections: [row], initialQuery: { connection: row.id } });
  assert.match(container.querySelector('[aria-label="Connection validation results"]')?.textContent ?? "", /Selected project access verified/);
  assert.match(container.querySelector('[aria-label="Connection validation results"]')?.textContent ?? "", /Selected project read returned/);
  const results = container.querySelector('[aria-label="Connection collection results"]');
  assert.equal(results?.querySelectorAll("section").length, 1);
  assert.match(results?.textContent ?? "", /Deployment evidence/);
  assert.match(results?.textContent ?? "", /Latest result: Partial/);
  assert.match(results?.textContent ?? "", /1 projects · 1 partial · 0 failed/);
  assert.match(results?.textContent ?? "", /Project collection has incomplete coverage/);
  assert.equal(results?.querySelector("time")?.dateTime, completedAt);
  assert.ok([...container.querySelectorAll(".connection-health")].every((badge) => badge.textContent === "Needs attention"));
  assert.equal(calls.gcp, 0);
});
