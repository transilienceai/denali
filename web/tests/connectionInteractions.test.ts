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
function detailFixture(provider: Connection["provider"], shared: boolean): Connection {
  const nativeCredentials: Record<Connection["provider"], Connection["credential_reference"]> = {
    aws: { type: "aws_assume_role", role_arn: "arn:aws:iam::123456789012:role/FixtureReader" },
    azure: { type: "azure_multitenant_app", client_id: azureSource.application_client_id },
    entra: { type: "entra_multitenant_app", client_id: azureSource.application_client_id },
    gcp: { type: "gcp_service_account", principal_email: "reader@example.invalid" },
    github: { type: "github_app_installation", app_id: 1, installation_id: 10, app_slug: "fixture" },
    google_workspace: { type: "google_workspace_domain_wide_delegation", service_account: "reader@example.invalid", oauth_client_id: "100000000001" },
    azure_repos: { type: "azure_repos_service_principal", client_id: azureSource.application_client_id },
  };
  return {
    ...attached, id: `${shared ? "shared" : "native"}-${provider}`, provider, display_name: `Fixture ${provider}`, health_state: "healthy",
    credential_reference: shared ? provider === "github" ? attached.credential_reference : { type: `platform_shared_${provider}`, platform_connection_id: azureSource.id } : nativeCredentials[provider],
    declared_scopes: [provider === "aws" ? "aws.bedrock_agents" : provider === "azure" ? "azure.ai_services" : provider === "entra" ? "entra.ai_applications" : provider === "gcp" ? "gcp.vertex_ai" : provider === "google_workspace" ? "google_workspace.gemini_activity" : `${provider}.repository_metadata`],
    configuration: { account_id: "123456789012", coverage_mode: "selected", regions: ["us-east-1"], tenant_id: azureSource.tenant_id, subscriptions: [{ id: azureSource.target_id, name: "Fixture subscription" }], projects: [{ id: "fixture-project", number: "123456789012", name: "Fixture project" }], domain: "example.invalid", admin_email: "admin@example.invalid", organization: "fixture", account_login: "fixture", repositories: provider === "azure_repos" ? azureRepositories.slice(0, 2) : repositories.slice(0, 2), onboarding: { method: "google_workspace_domain_wide_delegation", status: "completed" } },
    setup_capabilities: Object.fromEntries(Object.keys(attached.setup_capabilities).map((key) => [key, true])) as Connection["setup_capabilities"],
  };
}
const catalog: ConnectionCatalog = {
  items: ["github", "gcp", "aws", "azure_repos"].map((provider) => ({ provider: provider as Connection["provider"], label: provider === "github" ? "GitHub" : provider === "gcp" ? "Google Cloud" : provider === "azure_repos" ? "Azure Repos" : "Amazon Web Services", onboarding_path: "shared", shared_enabled: true, native_available: true, supported_scopes: [], parity_gaps: [], reason: null, reason_code: null })),
  platform_only: false, platform_only_blockers: [],
};

let dom: JSDOM;
let server: ViteDevServer;
let Page: ComponentType<Parameters<typeof ConnectionsPage>[0]>;
let Application: ComponentType<{ canWrite?: boolean }>;
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
  const application = await server.ssrLoadModule("/src/App.tsx");
  Page = application.ConnectionsPage;
  Application = application.default;
  pageApi = (await server.ssrLoadModule("/src/api.ts")).api;
  originalApi = { ...pageApi };
});
beforeEach(() => {
  dom.window.history.replaceState(null, "", "/connections");
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

function Harness({ initialConnections = [], initialQuery = { new: "1", provider: "github" }, canWrite = true, onChangedOverride }: { initialConnections?: Connection[]; initialQuery?: Record<string, string>; canWrite?: boolean; onChangedOverride?: () => Promise<void> }) {
  const [rows, setRows] = useState(initialConnections);
  const [query, setQuery] = useState(initialQuery);
  // Match App.updateQuery's captured render snapshot. Functional updates here
  // would hide consecutive callbacks overwriting navigation from the same event.
  const update = (values: Record<string, string | null | undefined>) => {
    const next = { ...query };
    for (const [key, value] of Object.entries(values)) {
      if (value) next[key] = value;
      else delete next[key];
    }
    setQuery(next);
  };
  return createElement(Page, {
    connections: rows, selectedId: query.connection, showCreate: query.new === "1" || Boolean(query.onboarding), canWrite,
    navigation: { values: query, set: (key, value, defaultValue = "") => update({ [key]: value === defaultValue ? null : value }), clear: (keys) => update(Object.fromEntries(keys.map((key) => [key, null]))), update },
    onSelect: (id) => update({ connection: id || null, new: null, provider: null, manage: null, onboarding: null }),
    onShowCreate: (visible) => update(visible ? { new: "1", manage: null, onboarding: null } : { new: null, provider: null, manage: null, onboarding: null }),
    onChanged: async () => { await onChangedOverride?.(); setRows([...initialConnections.filter((row) => row.id !== nextAttachment.id), nextAttachment]); }, onOperationAccepted: (id, kind) => { acceptedOperations.push({ id, kind }); },
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
  assert.equal(document.activeElement, container.querySelector('[data-connector-focus="detail"]'));
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

test("read-only connection actions use native disabled semantics instead of pointer-only blocking", async () => {
  await mount({initialConnections:[azureAttached],initialQuery:{connection:azureAttached.id},canWrite:false});
  const detail=container.querySelector<HTMLElement>('[aria-label="Connection details"]')!;
  assert.match(detail.textContent ?? "", /Read-only access/);
  const actionButtons=[...detail.querySelectorAll<HTMLButtonElement>("button")];
  assert.ok(actionButtons.length>0);
  assert.ok(actionButtons.every((element)=>element.matches(":disabled")),"Not merely CSS pointer-event blocking: keyboard and assistive technology must know these actions are disabled");
  await click(button("Disconnect from Denali"));
  assert.equal(calls.localDisable.length,0);
});

for (const shared of [true, false]) for (const provider of ["aws", "azure", "entra", "gcp", "github", "google_workspace", "azure_repos"] as const) {
  test(`members can inspect ${shared ? "shared" : "native"} ${provider} without enabling action controls`, async () => {
    const connection = detailFixture(provider, shared);
    await mount({ initialConnections: [connection], initialQuery: { connection: connection.id }, canWrite: false });
    const detail = container.querySelector<HTMLElement>('[aria-label="Connection details"]')!;
    const actions = [...detail.querySelectorAll<HTMLButtonElement>("button:not(.connection-copy-button)")];
    assert.ok(actions.length > 0);
    assert.ok(actions.every((element) => element.matches(":disabled")), "Setup, validation, collection and lifecycle actions must be natively disabled");
    assert.equal(detail.querySelector(".connection-launch-actions a"), null, "Members must not receive provider setup links");
    assert.equal(detail.querySelector("fieldset.connection-detail-access[disabled]"), null, "Do not disable the entire inspection surface");
    for (const action of actions) await click(action);
    assert.equal(calls.localDisable.length, 0);
    assert.equal(acceptedOperations.length, 0);
  });
}

test("members retain GitHub validation filtering and evidence disclosure", async () => {
  const connection = detailFixture("github", true);
  connection.last_validation = { started_at: "2026-10-15T10:00:00Z", completed_at: "2026-10-15T10:01:00Z", credential_state: "passed", health_state: "partial", account_id_observed: "1", summary: "One repository needs attention", results: repositories.slice(0, 2).map((repository, index) => ({ scope: "github.repository_metadata", plane: "repository_metadata", label: "Repository metadata", region: "global", repository_id: repository.id, repository_full_name: repository.full_name, state: index === 0 ? "failed" : "passed", detail: index === 0 ? "Fixture denied" : "Fixture passed" })) };
  await mount({ initialConnections: [connection], initialQuery: { connection: connection.id }, canWrite: false });
  const filters = container.querySelector<HTMLElement>('[aria-label="Filter repository validation results"]')!;
  assert.ok([...filters.querySelectorAll("button")].every((element) => !element.matches(":disabled")));
  const visible = () => [...container.querySelectorAll(".github-repository-validations details summary strong")].map((element) => element.textContent);
  assert.deepEqual(visible(), [repositories[0].full_name]);
  await click(filters.querySelectorAll<HTMLButtonElement>("button")[2]);
  assert.deepEqual(visible(), [repositories[1].full_name]);
  const evidence = container.querySelector<HTMLDetailsElement>(".github-repository-validations details")!;
  assert.equal(evidence.open, false);
  await click(evidence.querySelector("summary")!);
  assert.equal(evidence.open, true);
  await click(filters.querySelectorAll<HTMLButtonElement>("button")[1]);
  assert.deepEqual(visible(), [repositories[0].full_name, repositories[1].full_name]);
  assert.ok(button("Validate again").matches(":disabled"));
  assert.ok(button("Disconnect from Denali").matches(":disabled"));
  assert.equal(calls.localDisable.length, 0);
  assert.equal(acceptedOperations.length, 0);
});

test("members can copy recorded Workspace values but cannot launch or verify setup", async () => {
  const connection = detailFixture("google_workspace", false);
  const writes: string[] = [];
  const original = Object.getOwnPropertyDescriptor(dom.window.navigator, "clipboard");
  Object.defineProperty(dom.window.navigator, "clipboard", { configurable: true, value: { writeText: async (value: string) => { writes.push(value); } } });
  try {
    await mount({ initialConnections: [connection], initialQuery: { connection: connection.id }, canWrite: false });
    const value = container.querySelector<HTMLTextAreaElement>('[aria-label="Google Workspace OAuth client ID"]')!;
    assert.equal(value.readOnly, true);
    assert.equal(value.matches(":disabled"), false);
    assert.equal(button("Copy client ID").matches(":disabled"), false);
    await click(button("Copy client ID"));
    assert.deepEqual(writes, ["100000000001"]);
    assert.match(container.textContent ?? "", /Client ID copied to your clipboard/);
    assert.equal(container.querySelector('a[href*="admin.google.com"]'), null);
    assert.ok(button("Verify authorization again").matches(":disabled"));
    assert.ok(button("Validate connection").matches(":disabled"));
  } finally {
    if (original) Object.defineProperty(dom.window.navigator, "clipboard", original);
    else Reflect.deleteProperty(dom.window.navigator, "clipboard");
  }
});

test("setup receives keyboard focus and Close restores its Add or Manage opener", async () => {
  await mount({initialConnections:[attached], initialQuery:{connection:attached.id}});
  button("Add connection").focus();
  await click(button("Add connection"));
  assert.equal(document.activeElement, container.querySelector(".connection-wizard-heading h3"));
  assert.equal(container.querySelector(".connections-layout"), null, "Old connection actions must not compete with setup");
  await click(container.querySelector<HTMLButtonElement>('[aria-label="Close connection setup"]')!);
  assert.equal(document.activeElement, button("Add connection"));
  button("Manage access and selected resources").focus();
  await click(button("Manage access and selected resources"));
  assert.equal(document.activeElement, container.querySelector(".connection-wizard-heading h3"));
  await click(container.querySelector<HTMLButtonElement>('[aria-label="Close connection setup"]')!);
  assert.equal(document.activeElement, button("Manage access and selected resources"));
  assert.match(container.querySelector(".connection-list button.active")?.textContent ?? "", /Selected GitHub repositories/);
});

test("native exact AWS shows only its required code-to-cloud card, never required discovery scopes", async () => {
  pageApi.connectionCatalog = async () => ({...catalog,items:[{...catalog.items.find((item) => item.provider === "aws")!,onboarding_path:"native",shared_enabled:false}]});
  await mount({initialQuery:{new:"1",provider:"aws"}});
  const coverage = [...container.querySelectorAll<HTMLSelectElement>("select")].find((field) => field.closest("label")?.textContent?.includes("Inventory region coverage"))!;
  await select(coverage,"selected-resource");
  const choices = [...container.querySelectorAll<HTMLInputElement>('.connector-evidence-picker input[type="checkbox"]')];
  assert.equal(choices.length,1);
  assert.equal(choices[0].checked,true);
  assert.equal(choices[0].disabled,true);
  assert.match(choices[0].closest("label")?.textContent ?? "", /Code-to-cloud deployments.*Required/);
  assert.doesNotMatch(container.querySelector(".connector-evidence-picker")?.textContent ?? "", /Bedrock Agents|CloudTrail|AgentCore/);
  assert.equal(calls.native,0);
});

test("catalog loading is announced immediately without a false empty form", async () => {
  let finish!: (value: ConnectionCatalog) => void;
  pageApi.connectionCatalog = () => new Promise((resolve) => {finish=resolve;});
  await mount();
  assert.match(container.querySelector('[role="status"]')?.textContent ?? "", /Checking available connection methods/);
  assert.ok(container.querySelector('[aria-busy="true"]'));
  assert.equal(container.querySelector("form"),null);
  assert.equal(calls.github,0);
  await act(async () => finish(catalog));
  assert.equal(calls.github,1);
});

for (const hasExisting of [true, false]) test(`real App native creation selects the returned connection atomically (${hasExisting ? "existing selection" : "first connection"})`, async () => {
  const previous = { ...detailFixture("aws", false), id: "60000000-0000-0000-0000-000000000001", display_name: "Existing AWS connection" };
  const created = { ...previous, id: "60000000-0000-0000-0000-000000000002", display_name: "New AWS connection", credential_reference: { type: "aws_assume_role" as const, role_arn: "arn:aws:iam::123456789012:role/SeparateNewReader" } };
  let rows = hasExisting ? [previous] : [];
  let launches = 0;
  // Fail closed: this full App test may only call these synthetic read stubs.
  Object.assign(pageApi, Object.fromEntries(Object.keys(pageApi).map((name) => [name, async () => { throw new Error(`Unexpected API method in App navigation test: ${name}`); }])));
  Object.assign(pageApi, Object.fromEntries(["summary", "findingSummary", "vulnerabilitySummary", "issueSummary", "activitySummary", "detectionSummary"].map((name) => [name, async () => ({})])));
  Object.assign(pageApi, Object.fromEntries(["assets", "coverage", "findings", "vulnerabilities", "issues", "issueEvaluations", "codeToCloudDeployments", "codeToCloudObservations", "activity", "runtimeSessions", "detections", "detectionEvaluations"].map((name) => [name, async () => ({ items: [] })])));
  Object.assign(pageApi, {
    connections: async () => ({ items: rows }),
    connectionCatalog: async () => ({ ...catalog, items: [{ ...catalog.items.find((item) => item.provider === "aws")!, onboarding_path: "native", shared_enabled: false }] }),
    createConnection: async () => { calls.native += 1; rows = [...rows, created]; return created; },
    launchCloudFormation: async () => { launches += 1; throw new Error("No provider launch is allowed in this test"); },
  });
  dom.window.history.replaceState(null, "", `/connections?${hasExisting ? `connection=${previous.id}&` : ""}new=1&provider=aws`);
  const pushed: string[] = [];
  const originalPush = dom.window.history.pushState;
  dom.window.history.pushState = function (data, unused, url) { pushed.push(String(url)); return originalPush.call(this, data, unused, url); };
  try {
    await act(async () => { root.render(createElement(Application)); });
    const form = container.querySelector<HTMLFormElement>("form.connection-create");
    assert.ok(form, "The real App must display native AWS setup");
    await act(async () => { form.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true })); });
    assert.equal(calls.native, 1);
    assert.deepEqual(pushed, [`/connections?connection=${created.id}`], "Creation must make one atomic selection/close transition");
    const query = new URL(dom.window.location.href).searchParams;
    assert.equal(query.get("connection"), created.id);
    for (const key of ["new", "provider", "manage", "onboarding"]) assert.equal(query.has(key), false);
    assert.match(container.querySelector(".connection-list button.active")?.textContent ?? "", /New AWS connection/);
    assert.match(container.querySelector(".connection-detail-head code")?.textContent ?? "", /SeparateNewReader/);
    assert.equal(container.querySelector(".connection-onboarding-wizard"), null);
    assert.equal(document.activeElement, container.querySelector('[data-connector-focus="detail"]'));
    assert.equal(launches, 0);
    assert.equal(rows.filter((row) => row.id === previous.id).length, hasExisting ? 1 : 0);
  } finally { dom.window.history.pushState = originalPush; }
});

async function renderNativeAwsDetail(connection: Connection) {
  await act(async () => { root.render(createElement(Page, {
    connections: [connection], selectedId: connection.id, showCreate: false, canWrite: true,
    navigation: { values: { connection: connection.id }, set: () => {}, clear: () => {}, update: () => {} },
    onSelect: () => {}, onShowCreate: () => {}, onChanged: async () => {}, onOperationAccepted: () => {},
    entraSetupReturn: null, githubSetupReturn: null, azureReposSetupReturn: null,
  })); });
}

function previousFailedAwsValidation(): Connection {
  return {
    ...detailFixture("aws", false), health_state: "unhealthy", validation_state: "running",
    last_validated_at: "2026-10-19T00:15:00Z",
    last_validation: {
      started_at: "2026-10-19T00:00:00Z", completed_at: "2026-10-19T00:15:00Z", credential_state: "failed", health_state: "unhealthy", account_id_observed: null,
      summary: "Previous AccessDenied from the earlier run", results: [{ scope: "aws.bedrock_agents", plane: "credential", label: "Role assumption", region: "global", state: "failed", detail: "Previous AccessDenied from the earlier run" }],
    },
  };
}

test("reloaded AWS validation makes an earlier failure explicitly historical and collapsed", async () => {
  await renderNativeAwsDetail(previousFailedAwsValidation());
  const pending = container.querySelector('[aria-label="AWS validation in progress"] [role="status"]');
  assert.match(pending?.textContent ?? "", /Current validation is in progress/);
  assert.match(pending?.textContent ?? "", /previous result is historical/);
  assert.doesNotMatch(pending?.textContent ?? "", /AccessDenied/);
  const history = container.querySelector<HTMLDetailsElement>('details[aria-label="Previous AWS validation result"]');
  assert.ok(history);
  assert.equal(history.open, false);
  assert.equal(history.querySelector("summary time")?.getAttribute("datetime"), "2026-10-19T00:15:00Z");
  assert.match(history.textContent ?? "", /Previous AccessDenied/);
  assert.equal(container.querySelector(".validation-summary")?.closest("details"), history);
  assert.ok([...container.querySelectorAll(".connection-health")].every((badge) => badge.textContent === "Validating"));
});

test("an AWS launch marks old results historical before the durable running response arrives", async () => {
  let failLaunch!: (cause: Error) => void;
  pageApi.launchCloudFormation = () => new Promise((_, reject) => { failLaunch = reject; });
  const originalOpen = dom.window.open;
  dom.window.open = () => ({ opener: null, close: () => {}, location: { replace: () => {} } }) as unknown as Window;
  try {
    await renderNativeAwsDetail({ ...previousFailedAwsValidation(), validation_state: "idle" });
    await click(button("Launch in AWS"));
    assert.match(container.querySelector('[aria-label="AWS validation in progress"]')?.textContent ?? "", /Current validation is in progress/);
    assert.equal(container.querySelector<HTMLDetailsElement>('[aria-label="Previous AWS validation result"]')?.open, false);
    await act(async () => { failLaunch(new Error("Synthetic launch stopped before opening AWS")); });
  } finally { dom.window.open = originalOpen; }
});

test("a reloaded AWS retry does not reuse an earlier credential pass as current proof", async () => {
  const previous = previousFailedAwsValidation();
  await renderNativeAwsDetail({ ...previous, health_state: "healthy", last_validation: { ...previous.last_validation!, credential_state: "passed", health_state: "healthy", summary: "Previous credential pass" } });
  assert.equal(container.querySelector<HTMLDetailsElement>('[aria-label="Previous AWS validation result"]')?.open, false);
  assert.match(container.querySelector('[aria-label="Previous AWS validation result"]')?.textContent ?? "", /Previous credential pass/);
  assert.match(container.querySelector(".connection-operation-status")?.textContent ?? "", /Verifying the AWS role and declared access/);
  assert.equal(container.querySelector(".setup-progress > div:nth-child(2)")?.className, "current");
  assert.equal(container.querySelector(".setup-progress > div:nth-child(3)")?.className, "current");
  assert.equal(container.querySelector(".setup-progress > div:nth-child(3) > span")?.textContent, "3");
  assert.equal(container.querySelector(".setup-progress > div:nth-child(3) > span svg"), null);
  assert.equal(button("Verifying AWS access…").disabled, true);
});

test("an exact-resource AWS retry shows the current verification step above historical failure", async () => {
  const previous = previousFailedAwsValidation();
  await renderNativeAwsDetail({ ...previous, declared_scopes: ["aws.code_to_cloud"], configuration: { ...previous.configuration, coverage_mode: "selected-resource" } });
  assert.match(container.querySelector(".setup-progress > div:nth-child(3)")?.textContent ?? "", /Verify the selected resource and role/);
  assert.equal(container.querySelector(".setup-progress > div:nth-child(3)")?.className, "current");
  const history = container.querySelector<HTMLDetailsElement>('[aria-label="Previous AWS validation result"]');
  assert.equal(history?.open, false);
  assert.match(history?.textContent ?? "", /Previous AccessDenied/);
  assert.match(container.querySelector('[aria-label="AWS validation in progress"] [role="status"]')?.textContent ?? "", /Current validation is in progress/);
});

test("AWS validation without any historical result shows pending rather than a coverage conclusion", async () => {
  await renderNativeAwsDetail({ ...previousFailedAwsValidation(), last_validation: null, last_validated_at: null, health_state: "unknown" });
  const pending = container.querySelector('[aria-label="AWS validation in progress"]');
  assert.match(pending?.textContent ?? "", /No result has been recorded for this run yet/);
  assert.doesNotMatch(pending?.textContent ?? "", /Not validated|AccessDenied/);
  assert.equal(container.querySelector('[aria-label="Previous AWS validation result"]'), null);
});

for (const outcome of ["healthy", "unhealthy"] as const) test(`a fresh AWS ${outcome} result replaces the historical presentation`, async () => {
  const previous = previousFailedAwsValidation();
  await renderNativeAwsDetail(previous);
  await renderNativeAwsDetail({ ...previous, validation_state: "idle", health_state: outcome, last_validated_at: "2026-10-19T00:30:00Z", last_validation: {
    ...previous.last_validation!, completed_at: "2026-10-19T00:30:00Z", health_state: outcome, credential_state: outcome === "healthy" ? "passed" : "failed", summary: `Fresh ${outcome} result`, results: [],
  } });
  assert.equal(container.querySelector('[aria-label="AWS validation in progress"]'), null);
  assert.equal(container.querySelector('[aria-label="Previous AWS validation result"]'), null);
  assert.match(container.querySelector(".validation-summary")?.textContent ?? "", new RegExp(`Fresh ${outcome} result`));
  assert.doesNotMatch(container.textContent ?? "", /Previous AccessDenied/);
});

for (const coverageMode of ["selected", "automatic"] as const) test(`native AWS ${coverageMode} setup preserves existing stacks and roles`, async () => {
  const connection = detailFixture("aws", false);
  await renderNativeAwsDetail({ ...connection, configuration: { ...connection.configuration, coverage_mode: coverageMode } });
  const setup = container.querySelector(".setup-progress")?.textContent ?? "";
  assert.match(setup, /Preserve any existing stacks and roles/);
  assert.match(setup, /separate stack and a unique IAM role name/);
  assert.match(setup, /stop and review the collision instead of deleting or replacing/);
  assert.match(setup, /runtime caller policy to permit sts:AssumeRole for that exact role ARN/);
  assert.match(setup, /Ask the operator to review this before launch; do not widen that policy automatically/);
  assert.doesNotMatch(setup, /delete that stack|wait for its role to be removed|launching the replacement/);
});

test("abandoned native creation cannot refresh or select another setup after it resolves", async () => {
  pageApi.connectionCatalog = async () => ({...catalog,items:[{...catalog.items.find((item) => item.provider === "aws")!,onboarding_path:"native",shared_enabled:false}]});
  let finish!: (value: Connection) => void;
  let created=0;
  let refreshed=0;
  pageApi.createConnection = () => {created+=1;return new Promise((resolve) => {finish=resolve;});};
  await mount({initialConnections:[attached],initialQuery:{new:"1",provider:"aws"},onChangedOverride:async()=>{refreshed+=1;}});
  const form=container.querySelector<HTMLFormElement>("form.connection-create")!;
  await act(async () => {
    form.dispatchEvent(new dom.window.Event("submit",{bubbles:true,cancelable:true}));
    form.dispatchEvent(new dom.window.Event("submit",{bubbles:true,cancelable:true}));
  });
  assert.equal(created,1,"Synchronous double dispatch must not create two records");
  await click(container.querySelector<HTMLButtonElement>('[aria-label="Close connection setup"]')!);
  await act(async () => finish({...attached,id:"abandoned-native",display_name:"Abandoned native plan"}));
  assert.equal(refreshed,0);
  assert.ok(button("Add connection"));
  assert.doesNotMatch(container.textContent ?? "", /Abandoned native plan onboarding plan created/);
});

test("switching a pending native create back to reusable access fences its late result", async () => {
  let finish!: (value: Connection) => void;
  let refreshed=0;
  pageApi.createConnection = () => new Promise((resolve) => {finish=resolve;});
  await mount({initialConnections:[attached],initialQuery:{new:"1",provider:"github"},onChangedOverride:async()=>{refreshed+=1;}});
  await click(button("Use Denali setup instead"));
  const form=container.querySelector<HTMLFormElement>("form.connection-create")!;
  await act(async () => {form.dispatchEvent(new dom.window.Event("submit",{bubbles:true,cancelable:true}));});
  await click(button("Use reusable connection setup"));
  await act(async () => finish({...attached,id:"abandoned-native",display_name:"Abandoned native plan"}));
  assert.equal(refreshed,0);
  assert.ok(container.querySelector('[aria-label="GitHub access and repository selection"]'));
  assert.equal(container.querySelector("form.connection-create"),null);
  assert.doesNotMatch(container.textContent ?? "", /Abandoned native plan onboarding plan created/);
});

test("closing native setup during its refresh does not select the completed plan", async () => {
  pageApi.connectionCatalog = async () => ({...catalog,items:[{...catalog.items.find((item) => item.provider === "aws")!,onboarding_path:"native",shared_enabled:false}]});
  let finishRefresh!: () => void;
  pageApi.createConnection = async () => ({...attached,id:"late-native",display_name:"Late native plan"});
  await mount({initialConnections:[attached],initialQuery:{new:"1",provider:"aws"},onChangedOverride:()=>new Promise<void>((resolve)=>{finishRefresh=resolve;})});
  await act(async () => {container.querySelector<HTMLFormElement>("form.connection-create")!.dispatchEvent(new dom.window.Event("submit",{bubbles:true,cancelable:true}));});
  await click(container.querySelector<HTMLButtonElement>('[aria-label="Close connection setup"]')!);
  await act(async () => finishRefresh());
  assert.match(container.querySelector(".connection-list button.active")?.textContent ?? "", /Selected GitHub repositories/);
  assert.doesNotMatch(container.textContent ?? "", /Late native plan onboarding plan created/);
  assert.equal(document.activeElement,button("Add connection"));
});

test("a new provider does not mislabel an abandoned native request as its own creation", async () => {
  pageApi.connectionCatalog = async () => ({...catalog,items:catalog.items.map((item)=>({...item,onboarding_path:"native" as const,shared_enabled:false}))});
  let finish!: (value: Connection) => void;
  pageApi.createConnection = () => new Promise((resolve) => {finish=resolve;});
  await mount({initialConnections:[attached],initialQuery:{new:"1",provider:"aws"}});
  await act(async () => {container.querySelector<HTMLFormElement>("form.connection-create")!.dispatchEvent(new dom.window.Event("submit",{bubbles:true,cancelable:true}));});
  await click(button("GitHub"));
  assert.match(container.querySelector('[role="status"]')?.textContent ?? "", /A previous setup request is finishing/);
  assert.doesNotMatch(container.textContent ?? "", /Creating the GitHub onboarding plan/);
  assert.equal(button("Create onboarding plan").disabled,true);
  await act(async () => finish({...attached,id:"abandoned-native"}));
  assert.equal(button("Create onboarding plan").disabled,false);
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
