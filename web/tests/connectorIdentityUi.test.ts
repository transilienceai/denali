import assert from "node:assert/strict";
import { after, afterEach, before, beforeEach, test } from "node:test";
import { fileURLToPath } from "node:url";
import { act, createElement, useState, type ComponentType } from "react";
import { JSDOM } from "jsdom";
import { createServer, type ViteDevServer } from "vite";
import type { createRoot as CreateRoot, Root } from "react-dom/client";
import type { api, SharedAzureReposConnection, SharedGoogleWorkspaceStatus } from "../src/api.ts";
import type { SharedConnectionAdapterProps } from "../src/sharedConnectionAdapter.ts";
import type { Connection } from "../src/types.ts";

const githubRepository = (id: number) => ({ id, node_id: `node-${id}`, name: `repo-${String(id).padStart(3, "0")}`, full_name: `fixture/repo-${String(id).padStart(3, "0")}`, owner_id: 7, owner_login: "fixture", private: true, archived: false, default_branch: "main" });
const github = { id: "github-source", provider: "github" as const, connection_kind: "shared_github" as const, account_id: 7, account_login: "fixture", installation_id: 10, repository_selection: "all" as const, repository_count: 3, availability: "ready" as const, validated_scopes: ["github.repository_metadata"], last_validated_at: "2026-10-16T00:00:00Z" };
const azureRepository = (id: number) => ({ id: `00000000-0000-0000-0000-${String(id).padStart(12, "0")}`, project_id: "10000000-0000-0000-0000-000000000001", name: `repo-${id}`, project_name: "Fixture", full_name: `Fixture/repo-${id}`, default_branch: "refs/heads/main" });
const azure: SharedAzureReposConnection = { id: "azure-source", provider: "azure_repos", connection_kind: "shared_azure_repos", target_id: "azure-target", tenant_id: "azure-tenant", organization: "fixture", application_client_id: "azure-app", display_name: "Fixture repositories", lifecycle_state: "active", setup_state: "ready", health_state: "healthy", availability: "ready", repository_count: 3, authority_revision: 1, declared_scopes: ["azure_repos.repository_metadata", "azure_repos.repository_contents"], validated_scopes: ["azure_repos.repository_metadata", "azure_repos.repository_contents"], last_validated_at: "2026-10-16T00:00:00Z" };
const workspace: SharedGoogleWorkspaceStatus = {
  id: "workspace-source", clerk_org_id: "org_fixture", provider: "google_workspace", target_id: "10000000-0000-0000-0000-000000000003",
  customer_id: "C01fixture", domain: "fixture.example", admin_email: "admin@fixture.example", service_account: "fixture-reader@fixture.iam.gserviceaccount.com", oauth_client_id: "123456789012345678901",
  binding_revision: 1, lifecycle_state: "active", setup_state: "ready", health_state: "healthy", last_validated_at: new Date().toISOString(),
  declared_scopes: ["google_workspace.gemini_activity", "google_workspace.oauth_activity"], validated_scopes: ["google_workspace.gemini_activity", "google_workspace.oauth_activity"],
  validation_results: [
    { scope: "google_workspace.gemini_activity", application_name: "gemini_in_workspace_apps", state: "passed", customer_identity_observed: true },
    { scope: "google_workspace.oauth_activity", application_name: "token", state: "passed", customer_identity_observed: true },
  ],
};
const workspaceConfig = { enabled: true, items: [workspace], declared_scopes: [...workspace.declared_scopes], authorization_scope: "https://www.googleapis.com/auth/admin.reports.audit.readonly", setup_method: "domain_wide_delegation" };
const attached: Connection = { id: "local-github", provider: "github", display_name: "Exact saved repositories", lifecycle_state: "disabled", health_state: "unknown", credential_reference: { type: "platform_shared_github", platform_connection_id: github.id, installation_id: github.installation_id }, declared_scopes: [...github.validated_scopes], coverage_plan: [], configuration: { repositories: [githubRepository(2)] }, setup_capabilities: { cloudformation_quick_create: false, azure_cloud_shell: false, gcp_cloud_shell: false, github_app: false, entra_admin_consent: false, google_workspace_admin_authorization: false }, created_at: "2026-10-16T00:00:00Z", updated_at: "2026-10-16T00:00:00Z", last_validated_at: null, last_validation: null };

type Panel = ComponentType<SharedConnectionAdapterProps>;
type PickerProps = { items: Array<{ id: number; name: string }>; selected: number[]; onChange: (ids: number[]) => void; disabled?: boolean };
let dom: JSDOM;
let server: ViteDevServer;
let Github: Panel;
let Workspace: Panel;
let Azure: Panel;
let Picker: ComponentType<PickerProps>;
let createRoot: typeof CreateRoot;
let root: Root;
let container: HTMLDivElement;
let client: typeof api;
let originalApi: typeof api;
let mutations: number;
const globals = new Map<string, PropertyDescriptor | undefined>();

before(async () => {
  dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://denali.test/connections" });
  for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document, navigator: dom.window.navigator, HTMLElement: dom.window.HTMLElement, IS_REACT_ACT_ENVIRONMENT: true })) {
    globals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
  ({ createRoot } = await import("react-dom/client"));
  server = await createServer({ root: fileURLToPath(new URL("../", import.meta.url)), configFile: false, envDir: false, appType: "custom", server: { middlewareMode: true, ws: false, watch: null }, optimizeDeps: { noDiscovery: true } });
  Github = (await server.ssrLoadModule("/src/SharedGitHubPilot.tsx")).SharedGitHubPilot;
  Workspace = (await server.ssrLoadModule("/src/SharedGoogleWorkspacePilot.tsx")).SharedGoogleWorkspacePilot;
  Azure = (await server.ssrLoadModule("/src/SharedAzureReposPilot.tsx")).SharedAzureReposPilot;
  Picker = (await server.ssrLoadModule("/src/ConnectorRepositoryPicker.tsx")).ConnectorRepositoryPicker;
  client = (await server.ssrLoadModule("/src/api.ts")).api;
  originalApi = { ...client };
});
beforeEach(() => {
  mutations = 0;
  Object.assign(client, {
    sharedGithubConnections: async () => ({ items: [github] }),
    sharedGithubRepositories: async () => ({ items: [1, 2, 3].map(githubRepository) }),
    sharedGoogleWorkspaceConfig: async () => workspaceConfig,
    sharedGoogleWorkspaceInventory: async () => ({ items: [workspace] }),
    sharedGoogleWorkspaceStatus: async () => workspace,
    sharedAzureReposConfig: async () => ({ items: [azure] }),
    sharedAzureReposConnections: async () => ({ items: [azure] }),
    sharedAzureReposStatus: async () => azure,
    sharedAzureReposRepositories: async () => ({ items: [1, 2, 3].map(azureRepository) }),
    startSharedGithubSetup: async () => { mutations += 1; throw new Error("No provider launch in UI tests"); },
    startSharedGoogleWorkspaceSetup: async () => { mutations += 1; return workspace; },
    createSharedAzureRepos: async () => { mutations += 1; return { id: azure.id }; },
    useSharedGithubInDenali: async () => { mutations += 1; return attached; },
    useSharedAzureRepos: async () => { mutations += 1; return attached; },
    useSharedGoogleWorkspaceInDenali: async () => { mutations += 1; return attached; },
  });
  container = document.createElement("div"); document.body.append(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); Object.assign(client, originalApi); });
after(async () => {
  await server.close(); dom.window.close();
  for (const [key, descriptor] of globals) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function mount(Component: Panel, props: Partial<SharedConnectionAdapterProps> = {}) {
  await act(async () => { root.render(createElement(Component, { canWrite: true, onChanged: async () => {}, ...props })); });
}
async function click(element: HTMLElement) { await act(async () => element.click()); }
function button(label: string) {
  const result = [...container.querySelectorAll("button")].find((element) => element.textContent?.trim() === label);
  assert.ok(result, `Missing button: ${label}`); return result;
}
function choices() { return [...container.querySelectorAll<HTMLInputElement>(".repository-picker-item input")]; }
async function search(value: string) {
  const input = container.querySelector<HTMLInputElement>('input[type="search"]'); assert.ok(input);
  await act(async () => {
    Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
  });
}

test("GitHub announces delayed loading instead of rendering a false empty or authorization form", async () => {
  const pending = deferred<{ items: typeof github[] }>();
  client.sharedGithubConnections = () => pending.promise;
  await mount(Github);
  assert.match(container.textContent ?? "", /Loading authorized GitHub accounts/);
  assert.ok(container.querySelector('[aria-busy="true"]'));
  assert.equal(container.querySelector("select"), null);
  assert.doesNotMatch(container.textContent ?? "", /No authorized GitHub accounts|Manage repository access in GitHub/);
  await act(async () => pending.resolve({ items: [] }));
  assert.match(container.textContent ?? "", /No authorized GitHub accounts/);
  assert.ok(button("Manage repository access in GitHub"));
  assert.equal(mutations, 0);
});

test("GitHub failure remains an error with a working retry, not an empty catalog", async () => {
  client.sharedGithubConnections = async () => { throw new Error("Fixture access lookup failed"); };
  await mount(Github);
  assert.match(container.querySelector('[role="alert"]')?.textContent ?? "", /lookup failed/);
  assert.doesNotMatch(container.textContent ?? "", /No authorized GitHub accounts/);
  client.sharedGithubConnections = async () => ({ items: [] });
  await click(button("Try again"));
  assert.equal(container.querySelector('[role="alert"]'), null);
  assert.match(container.textContent ?? "", /No authorized GitHub accounts/);
  assert.equal(mutations, 0);
});

test("Workspace waits for both catalogs, prioritizes authorized access and explicitly expands a new plan", async () => {
  const config = deferred<typeof workspaceConfig>();
  const inventory = deferred<{ items: typeof workspace[] }>();
  client.sharedGoogleWorkspaceConfig = () => config.promise;
  client.sharedGoogleWorkspaceInventory = () => inventory.promise;
  await mount(Workspace);
  assert.match(container.textContent ?? "", /Loading approved Workspace access/);
  assert.equal(container.querySelector("form"), null);
  assert.doesNotMatch(container.textContent ?? "", /No approved Workspace targets/);
  await act(async () => config.resolve(workspaceConfig));
  assert.equal(container.querySelector("form"), null);
  await act(async () => inventory.resolve({ items: [workspace] }));
  const form = container.querySelector("form"); assert.ok(form);
  const disclosure = form.closest("details"); assert.ok(disclosure); assert.equal(disclosure.open, false);
  const source = container.querySelector(".shared-aws-pilot-detail"); assert.ok(source);
  assert.ok(source.compareDocumentPosition(disclosure) & dom.window.Node.DOCUMENT_POSITION_FOLLOWING);
  await click(disclosure.querySelector("summary")!);
  assert.equal(disclosure.open, true);
  assert.ok([...container.querySelectorAll<HTMLInputElement>('.connector-evidence-picker input')].every((input) => input.checked && input.disabled));
  assert.equal(mutations, 0);
});

test("Workspace explicitly waits for current exact-customer proof before enabling attachment", async () => {
  const pending = deferred<SharedGoogleWorkspaceStatus>(); client.sharedGoogleWorkspaceStatus = () => pending.promise;
  await mount(Workspace);
  assert.match(container.textContent ?? "", /Checking current Workspace access/);
  assert.equal(button("Use in Denali").disabled, true);
  await act(async () => pending.resolve(workspace));
  assert.equal(button("Use in Denali").disabled, false);
  assert.equal(mutations, 0);
});

test("Workspace never falls back from an unavailable pinned attachment to another customer", async () => {
  const connection = { ...attached, provider: "google_workspace", credential_reference: { type: "platform_shared_google_workspace", platform_connection_id: "missing-source" } } as Connection;
  await mount(Workspace, { connection });
  assert.match(container.querySelector('[role="alert"]')?.textContent ?? "", /original Workspace connection is unavailable/);
  assert.equal(container.querySelector("select"), null);
  assert.equal(container.querySelector("form"), null);
  assert.doesNotMatch(container.textContent ?? "", /Use in Denali/);
  assert.equal(mutations, 0);
});

test("Workspace ignores an older delayed catalog after a newer focus refresh succeeds", async () => {
  const firstConfig = deferred<typeof workspaceConfig>(); const firstInventory = deferred<{ items: typeof workspace[] }>();
  let configs = 0; let inventories = 0;
  client.sharedGoogleWorkspaceConfig = () => ++configs === 1 ? firstConfig.promise : Promise.resolve(workspaceConfig);
  client.sharedGoogleWorkspaceInventory = () => ++inventories === 1 ? firstInventory.promise : Promise.resolve({ items: [workspace] });
  await mount(Workspace);
  await act(async () => dom.window.dispatchEvent(new dom.window.Event("focus")));
  assert.match(container.textContent ?? "", /fixture\.example/);
  await act(async () => { firstConfig.resolve(workspaceConfig); firstInventory.resolve({ items: [{ ...workspace, id: "old-source", domain: "old.example" }] }); });
  assert.doesNotMatch(container.textContent ?? "", /old\.example/);
  assert.equal(mutations, 0);
});

test("Azure Repos hides setup while either catalog is pending and retains mandatory metadata defaults", async () => {
  const listing = deferred<{ items: SharedAzureReposConnection[] }>();
  client.sharedAzureReposConnections = () => listing.promise;
  await mount(Azure);
  assert.match(container.textContent ?? "", /Loading approved Azure DevOps organizations/);
  assert.equal(container.querySelector("form"), null);
  assert.doesNotMatch(container.textContent ?? "", /No approved Azure DevOps targets/);
  await act(async () => listing.resolve({ items: [] }));
  const form = container.querySelector("form"); assert.ok(form);
  const scopes = [...form.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
  assert.equal(scopes.length, 2); assert.equal(scopes[0].disabled, true); assert.equal(scopes[0].checked, true); assert.equal(scopes[1].checked, true);
  await click(scopes[1]); assert.equal(scopes[0].checked, true); assert.equal(scopes[1].checked, false);
  assert.equal(mutations, 0);
});

test("Azure Repos prioritizes the authorized source and keeps another-plan creation collapsed", async () => {
  await mount(Azure);
  const form = container.querySelector("form"); assert.ok(form);
  const disclosure = form.closest("details"); assert.ok(disclosure); assert.equal(disclosure.open, false);
  assert.ok(container.querySelector(".shared-aws-pilot-detail")!.compareDocumentPosition(disclosure) & dom.window.Node.DOCUMENT_POSITION_FOLLOWING);
  assert.equal(choices().length, 3); assert.ok(choices().every((input) => !input.checked));
  assert.equal(mutations, 0);
});

test("Azure Repos delays repository review and attachment while exact candidates are loading", async () => {
  const pending = deferred<{ items: ReturnType<typeof azureRepository>[] }>(); client.sharedAzureReposRepositories = () => pending.promise;
  await mount(Azure);
  assert.match(container.textContent ?? "", /Checking verified repository identities/);
  assert.doesNotMatch(container.textContent ?? "", /0 verified repositories/);
  assert.equal(button("Use selected repositories in Denali").disabled, true);
  assert.equal(choices().length, 0);
  await act(async () => pending.resolve({ items: [1, 2, 3].map(azureRepository) }));
  await click(choices()[1]); assert.equal(button("Use selected repositories in Denali").disabled, false);
  assert.equal(mutations, 0);
});

function PickerHarness({ disabled = false }: { disabled?: boolean }) {
  const [ids, setIds] = useState([2, 80]);
  return createElement("div", null, createElement(Picker, { items: Array.from({ length: 125 }, (_, index) => ({ id: index + 1, name: githubRepository(index + 1).full_name })), selected: ids, onChange: setIds, disabled }), createElement("output", { "data-selection": true }, JSON.stringify(ids)));
}

test("repository filtering and bounded pages preserve hidden selections and never check additions", async () => {
  await act(async () => root.render(createElement(PickerHarness)));
  assert.equal(choices().length, 50); assert.equal(choices().filter((input) => input.checked).length, 1);
  assert.match(container.textContent ?? "", /2 selected.*125 available/s);
  await search("repo-080"); assert.equal(choices().length, 1); assert.equal(choices()[0].checked, true);
  await click(choices()[0]); assert.equal(container.querySelector("output")?.textContent, "[2]");
  await search(""); assert.equal(choices().length, 50); assert.equal(choices()[1].checked, true);
  await click(button("Next")); assert.equal(choices().length, 50); assert.equal(choices()[29].checked, false);
  await click(choices()[29]); assert.equal(container.querySelector("output")?.textContent, "[2,80]");
  await search("no-match"); assert.equal(choices().length, 0); assert.match(container.textContent ?? "", /No repositories match this search/);
  assert.equal(container.querySelector("output")?.textContent, "[2,80]");
  await click(button("Clear search")); assert.equal(choices().length, 50); assert.equal(choices()[1].checked, true);
});

test("repository search, scroll region, pages and paired choices retain native keyboard semantics", async () => {
  await act(async () => root.render(createElement(PickerHarness, { disabled: true })));
  const searchInput = container.querySelector<HTMLInputElement>('input[type="search"]')!;
  assert.match(searchInput.labels?.[0]?.textContent ?? "", /Search repositories/);
  assert.equal(searchInput.maxLength, 200); searchInput.focus(); assert.equal(document.activeElement, searchInput);
  const list = container.querySelector<HTMLElement>('[aria-label="Available repositories"]')!;
  assert.equal(list.tabIndex, 0); list.focus(); assert.equal(document.activeElement, list);
  for (const input of choices()) { assert.equal(input.disabled, true); assert.ok(input.labels?.[0]?.textContent?.includes("fixture/repo-")); }
  assert.equal(button("Next").type, "button"); assert.equal(button("Previous").disabled, true);
  assert.equal(container.querySelector("output")?.textContent, "[2,80]");
});

test("GitHub search preserves an exact disabled attachment and does not select a new scope or repository", async () => {
  const rows = Array.from({ length: 125 }, (_, index) => githubRepository(index + 1));
  client.sharedGithubConnections = async () => ({ items: [{ ...github, repository_count: rows.length, validated_scopes: ["github.repository_metadata", "github.repository_contents"] }] });
  client.sharedGithubRepositories = async () => ({ items: rows });
  const original = JSON.stringify(attached);
  await mount(Github, { connection: attached });
  await search("repo-080"); await click(choices()[0]);
  await search("repo-002"); assert.equal(choices()[0].checked, true);
  assert.match(container.textContent ?? "", /1 saved · 2 in this review/);
  const scopeChoices = [...container.querySelectorAll<HTMLInputElement>('[aria-label="GitHub evidence selection"] input')];
  assert.equal(container.querySelector('[aria-label="GitHub evidence selection"]')?.tagName, "FIELDSET");
  assert.deepEqual(scopeChoices.map((input) => input.checked), [true, false]);
  assert.equal(JSON.stringify(attached), original); assert.equal(mutations, 0);
});

for (const name of ["GitHub", "Workspace", "Azure Repos"]) {
  test(`${name} read-only presentation has no privileged setup or attachment action`, async () => {
    await mount(name === "GitHub" ? Github : name === "Workspace" ? Workspace : Azure, { canWrite: false });
    assert.equal(container.querySelector("form"), null);
    assert.ok([...container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')].every((input) => input.disabled));
    assert.doesNotMatch([...container.querySelectorAll("button, a")].map((element) => element.textContent).join(" "), /Prepare|Use in Denali|Use selected|Manage repository access|Review Microsoft authorization|Open Google Admin Console|Disable access/);
    assert.equal(mutations, 0);
  });
}

for (const name of ["GitHub", "Workspace", "Azure Repos"]) {
  test(`${name} renders an explicit unavailable state and read-only retry after an admission 404`, async () => {
    const unavailable = async () => { throw Object.assign(new Error("Not enabled"), { status: 404 }); };
    if (name === "GitHub") client.sharedGithubConnections = unavailable;
    else if (name === "Workspace") client.sharedGoogleWorkspaceConfig = unavailable;
    else client.sharedAzureReposConfig = unavailable;
    await mount(name === "GitHub" ? Github : name === "Workspace" ? Workspace : Azure);
    assert.match(container.textContent ?? "", /Reusable .* access is unavailable/);
    assert.ok(button("Check organization access"));
    assert.equal(container.querySelector("form"), null);
    assert.equal(container.querySelector("select"), null);
    assert.doesNotMatch([...container.querySelectorAll("button")].map((element) => element.textContent).join(" "), /Prepare|Use in Denali|Use selected|Manage repository access|Disable access/);
    assert.equal(mutations, 0);
  });
}

const fixtureGithubAuthorization = `https://github.com/login/oauth/authorize?client_id=Iv1.fixture&redirect_uri=https%3A%2F%2Fplatform.example%2Fv1%2Fconnections%2Fgithub%2Foauth%2Fcallback&state=${"s".repeat(64)}&code_challenge=${"c".repeat(43)}&code_challenge_method=S256&allow_signup=false`;

for (const name of ["GitHub", "Azure Repos"]) {
  for (const abandon of ["unmount", "attachment_change"]) {
    test(`${name} ignores a delayed authorization response after ${abandon}`, async () => {
      const pending = deferred<{ install_url: string; authorize_url: string }>();
      let progress = 0; let navigation = 0;
      const onNavigation = () => { navigation += 1; };
      dom.virtualConsole.on("jsdomError", onNavigation);
      if (name === "GitHub") client.startSharedGithubSetup = () => pending.promise;
      else client.startSharedAzureReposSetup = () => pending.promise;
      const Component = name === "GitHub" ? Github : Azure;
      const props = { canWrite: true, onChanged: async () => {}, onProgress: () => { progress += 1; } };
      try {
        await mount(Component, props);
        const initialProgress = progress;
        await click(button(name === "GitHub" ? "Manage repository access in GitHub" : "Review Microsoft authorization"));
        assert.match(container.textContent ?? "", /Preparing .* authorization/);
        await act(async () => {
          root.render(abandon === "unmount" ? createElement("p", null, "Another provider")
            : createElement(Component, { ...props, connection: { ...attached, id: "different-local-attachment" } }));
        });
        await act(async () => pending.resolve({ install_url: fixtureGithubAuthorization, authorize_url: `https://login.microsoftonline.com/${azure.tenant_id}/oauth2/v2.0/authorize` }));
        assert.equal(progress, initialProgress);
        assert.equal(navigation, 0);
        if (abandon === "unmount") assert.equal(container.textContent, "Another provider");
      } finally { dom.virtualConsole.removeListener("jsdomError", onNavigation); }
    });
  }
}

for (const name of ["GitHub", "Workspace", "Azure Repos"]) {
  test(`${name} abandons a delayed attachment response without navigation or callbacks`, async () => {
    const pending = deferred<Connection>();
    let changed = 0; let attachedCalls = 0;
    if (name === "GitHub") client.useSharedGithubInDenali = () => pending.promise;
    else if (name === "Workspace") client.useSharedGoogleWorkspaceInDenali = () => pending.promise;
    else client.useSharedAzureRepos = () => pending.promise;
    await mount(name === "GitHub" ? Github : name === "Workspace" ? Workspace : Azure, { onChanged: async () => { changed += 1; }, onAttached: () => { attachedCalls += 1; } });
    if (name !== "Workspace") await click(choices()[0]);
    await click(button(name === "Workspace" ? "Use in Denali" : "Use selected repositories in Denali"));
    assert.match(container.textContent ?? "", /Saving the reviewed|Attaching the/);
    await act(async () => root.render(createElement("p", null, "Another provider")));
    await act(async () => pending.resolve(attached));
    assert.equal(changed, 0); assert.equal(attachedCalls, 0);
    assert.equal(container.textContent, "Another provider");
  });
}

test("an abandoned Workspace plan never performs refresh or status requests after its creation response", async () => {
  client.sharedGoogleWorkspaceInventory = async () => ({ items: [] });
  const pending = deferred<SharedGoogleWorkspaceStatus>();
  let statuses = 0; let configs = 0;
  client.startSharedGoogleWorkspaceSetup = () => pending.promise;
  client.sharedGoogleWorkspaceConfig = async () => { configs += 1; return workspaceConfig; };
  client.sharedGoogleWorkspaceStatus = async () => { statuses += 1; return workspace; };
  await mount(Workspace);
  await click(button("Prepare shared Workspace connection"));
  assert.match(container.textContent ?? "", /Preparing the approved Workspace connection/);
  await act(async () => root.render(createElement("p", null, "Another organization")));
  await act(async () => pending.resolve(workspace));
  assert.equal(configs, 1); assert.equal(statuses, 0);
  assert.equal(container.textContent, "Another organization");
});

test("Workspace does not dispatch attachment after a status response for an abandoned local context", async () => {
  const pending = deferred<SharedGoogleWorkspaceStatus>(); let reads = 0;
  client.sharedGoogleWorkspaceStatus = () => ++reads === 1 ? Promise.resolve(workspace) : pending.promise;
  await mount(Workspace);
  await click(button("Use in Denali"));
  await act(async () => root.render(createElement(Workspace, { canWrite: true, onChanged: async () => {}, connection: { ...attached, id: "changed-context" } })));
  await act(async () => pending.resolve(workspace));
  assert.equal(mutations, 0);
});

test("GitHub does not invoke the attachment callback after leaving during the app refresh", async () => {
  const pending = deferred<void>(); let attachedCalls = 0;
  await mount(Github, { onChanged: () => pending.promise, onAttached: () => { attachedCalls += 1; } });
  await click(choices()[0]); await click(button("Use selected repositories in Denali"));
  assert.equal(mutations, 1);
  await act(async () => root.render(createElement("p", null, "Another provider")));
  await act(async () => pending.resolve());
  assert.equal(attachedCalls, 0);
});

test("an action pending ref prevents duplicate GitHub setup dispatch before React rerenders", async () => {
  const pending = deferred<{ install_url: string }>(); let requests = 0;
  client.startSharedGithubSetup = () => { requests += 1; return pending.promise; };
  await mount(Github);
  const start = button("Manage repository access in GitHub");
  await act(async () => { start.click(); start.click(); });
  assert.equal(requests, 1);
  assert.match(container.textContent ?? "", /Preparing GitHub authorization/);
  await act(async () => pending.resolve({ install_url: "https://invalid.example/setup" }));
  assert.match(container.querySelector('[role="alert"]')?.textContent ?? "", /setup link is invalid/);
});
