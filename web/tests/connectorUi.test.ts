import assert from "node:assert/strict";
import { after, afterEach, before, beforeEach, test } from "node:test";
import { fileURLToPath } from "node:url";
import { act, createElement, useState, type ComponentType } from "react";
import { JSDOM } from "jsdom";
import { createServer, type ViteDevServer } from "vite";
import type { Root } from "react-dom/client";
import type { EvidenceScopePicker } from "../src/ConnectorUi.tsx";
import type { ConnectionOnboardingWizard } from "../src/ConnectionOnboardingWizard.tsx";
import type { ConnectionCatalogItem } from "../src/api.ts";

let dom: JSDOM;
let vite: ViteDevServer;
let root: Root;
let container: HTMLDivElement;
let Picker: ComponentType<Parameters<typeof EvidenceScopePicker>[0]>;
let Wizard: ComponentType<Parameters<typeof ConnectionOnboardingWizard>[0]>;
let createRoot: typeof import("react-dom/client").createRoot;
const globals = new Map<string, PropertyDescriptor | undefined>();
const items: ConnectionCatalogItem[] = ["aws", "azure", "github"].map((provider) => ({
  provider: provider as ConnectionCatalogItem["provider"], label: provider.toUpperCase(), onboarding_path: "shared", shared_enabled: true,
  native_available: true, supported_scopes: [], parity_gaps: [], reason: null, reason_code: null,
}));

before(async () => {
  dom = new JSDOM("<!doctype html><html><body></body></html>", {url: "https://denali.test/connections"});
  for (const [key, value] of Object.entries({window: dom.window, document: dom.window.document, navigator: dom.window.navigator, HTMLElement: dom.window.HTMLElement, IS_REACT_ACT_ENVIRONMENT: true})) {
    globals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, {configurable: true, writable: true, value});
  }
  ({createRoot} = await import("react-dom/client"));
  vite = await createServer({root: fileURLToPath(new URL("../", import.meta.url)), configFile: false, envDir: false, appType: "custom", server: {middlewareMode: true, ws: false, watch: null}, optimizeDeps: {noDiscovery: true}});
  Picker = (await vite.ssrLoadModule("/src/ConnectorUi.tsx")).EvidenceScopePicker;
  Wizard = (await vite.ssrLoadModule("/src/ConnectionOnboardingWizard.tsx")).ConnectionOnboardingWizard;
});
beforeEach(() => {
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); });
after(async () => {
  await vite?.close();
  dom?.window.close();
  for (const [key, descriptor] of globals) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
});

test("evidence cards pair controls with human labels without changing selection defaults", async () => {
  const changes: string[][] = [];
  await act(async () => root.render(createElement(Picker, {
    scopes: ["azure.ai_services", "azure.agent_runtime_activity"], selected: ["azure.ai_services"], onChange: (selection) => changes.push(selection), help: "Selected scopes only.",
  })));
  const fields = [...container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
  assert.deepEqual(fields.map((field) => field.checked), [true, false]);
  assert.equal(changes.length, 0);
  assert.match(fields[0].closest("label")?.textContent ?? "", /AI services/);
  assert.match(fields[1].closest("label")?.textContent ?? "", /Foundry runtime activity/);
  assert.ok(fields.every((field) => field.closest(".connector-choice")?.querySelector(".connector-choice-copy")));
  const help = container.querySelector("fieldset")?.getAttribute("aria-describedby");
  assert.ok(help && document.getElementById(help)?.textContent === "Selected scopes only.");
  await act(async () => fields[1].click());
  assert.deepEqual(changes, [["azure.ai_services", "azure.agent_runtime_activity"]]);
});

test("required evidence remains selected and non-editable without widening the bundle", async () => {
  const scopes = ["entra.ai_applications", "entra.permissions"];
  let changed = false;
  await act(async () => root.render(createElement(Picker, {scopes, selected: scopes, requiredScopes: scopes, onChange: () => {changed = true;}})));
  const fields = [...container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
  assert.ok(fields.every((field) => field.checked && field.disabled));
  await act(async () => fields[0].click());
  assert.equal(changed, false);
  assert.equal(fields.length, scopes.length);
});

test("provider tabs support arrow/Home/End navigation with matching panel labels", async () => {
  function Harness() {
    const [provider, setProvider] = useState<ConnectionCatalogItem["provider"]>("aws");
    return createElement(Wizard, {items, provider, loading: false, error: null, nativeRequested: false, phase: "grant", managing: false,
      onProvider: setProvider, onNative: () => {}, onRetry: () => {}, onClose: () => {}, children: createElement("p", null, `${provider} setup`)});
  }
  await act(async () => root.render(createElement(Harness)));
  const tabs = [...container.querySelectorAll<HTMLButtonElement>('[role="tab"]')];
  const panel = container.querySelector('[role="tabpanel"]')!;
  const checkSelected = (index: number) => {
    assert.deepEqual(tabs.map((tab) => tab.getAttribute("aria-selected")), tabs.map((_, candidate) => candidate === index ? "true" : "false"));
    assert.deepEqual(tabs.map((tab) => tab.tabIndex), tabs.map((_, candidate) => candidate === index ? 0 : -1));
    assert.equal(panel.getAttribute("aria-labelledby"), tabs[index].id);
    assert.equal(document.activeElement, tabs[index]);
  };
  tabs[0].focus();
  await act(async () => tabs[0].dispatchEvent(new dom.window.KeyboardEvent("keydown", {key: "ArrowRight", bubbles: true})));
  checkSelected(1);
  await act(async () => tabs[1].dispatchEvent(new dom.window.KeyboardEvent("keydown", {key: "End", bubbles: true})));
  checkSelected(2);
  await act(async () => tabs[2].dispatchEvent(new dom.window.KeyboardEvent("keydown", {key: "Home", bubbles: true})));
  checkSelected(0);
  await act(async () => tabs[0].dispatchEvent(new dom.window.KeyboardEvent("keydown", {key: "ArrowLeft", bubbles: true})));
  checkSelected(2);
  assert.match(panel.textContent ?? "", /github setup/);
});

test("an unavailable requested provider does not strand keyboard users outside the available tabs", async () => {
  const selected: string[]=[];
  await act(async () => root.render(createElement(Wizard, {items,provider:"gcp",loading:false,error:null,nativeRequested:false,phase:"grant",managing:false,onProvider:(provider)=>selected.push(provider),onNative:()=>{},onRetry:()=>{},onClose:()=>{},children:createElement("p",null,"Must not render missing adapter")})));
  const tabs=[...container.querySelectorAll<HTMLButtonElement>('[role="tab"]')];
  assert.deepEqual(tabs.map((tab)=>tab.tabIndex),[0,-1,-1]);
  assert.match(container.querySelector('[role="tabpanel"]')?.textContent ?? "", /Connection setup unavailable/);
  assert.doesNotMatch(container.textContent ?? "", /Must not render missing adapter/);
  await act(async () => tabs[0].click());
  assert.deepEqual(selected,["aws"]);
});
