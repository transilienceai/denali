import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { api, configureApiTokenProvider } from "../src/api.ts";

const originalFetch = globalThis.fetch;
afterEach(() => {
  configureApiTokenProvider(async () => null);
  globalThis.fetch = originalFetch;
});

test("an organization change aborts pending requests and discards a late response", async () => {
  let finish!: (response: Response) => void;
  let oldSignal: AbortSignal | null | undefined;
  globalThis.fetch = async (_url, init) => {
    oldSignal = init?.signal;
    return new Promise<Response>((resolve) => { finish = resolve; });
  };
  configureApiTokenProvider(async () => "organization-a");
  const pending = api.connections();
  const rejected = assert.rejects(pending, { name: "AbortError" });
  await Promise.resolve();
  configureApiTokenProvider(async () => "organization-b");
  assert.equal(oldSignal?.aborted, true);
  // Even a transport that ignores cancellation cannot publish the old payload.
  finish(new Response(JSON.stringify({ items: [{ id: "old-organization-connection" }] })));
  await rejected;
  let authorization = "";
  globalThis.fetch = async (_url, init) => {
    authorization = new Headers(init?.headers).get("Authorization") ?? "";
    return new Response(JSON.stringify({ items: [] }));
  };
  assert.deepEqual(await api.connections(), { items: [] });
  assert.equal(authorization, "Bearer organization-b");
});

test("switching organizations during token acquisition cannot dispatch a stale mutation", async () => {
  let finishToken!: (token: string) => void;
  let requests = 0;
  globalThis.fetch = async () => { requests += 1; return new Response("{}"); };
  configureApiTokenProvider(() => new Promise<string>((resolve) => { finishToken = resolve; }));
  const pending = api.startSharedGithubSetup({ request_id: "fixture-request" });
  const rejected = assert.rejects(pending, { name: "AbortError" });
  configureApiTokenProvider(async () => "organization-b");
  finishToken("organization-a");
  await rejected;
  assert.equal(requests, 0);
});

test("workspace authorization honors its caller cancellation signal", async () => {
  const controller = new AbortController();
  controller.abort();
  let requests = 0;
  globalThis.fetch = async () => { requests += 1; return new Response("{}"); };
  await assert.rejects(api.context(controller.signal), { name: "AbortError" });
  assert.equal(requests, 0);
});

test("catalog and workflow resume remain authenticated same-origin reads", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  globalThis.fetch = async (url, init) => {
    requests.push({ url: String(url), init });
    return new Response(JSON.stringify({ items: [], platform_only: false, platform_only_blockers: [] }));
  };
  configureApiTokenProvider(async () => "fixture-session");
  await api.connectionCatalog();
  await api.onboardingWorkflow("workflow/id");
  assert.deepEqual(requests.map((request) => request.url), ["/api/v1/connections/catalog", "/api/v1/connections/onboarding/workflow%2Fid"]);
  for (const request of requests) {
    assert.equal(request.init?.method ?? "GET", "GET");
    assert.equal(new Headers(request.init?.headers).get("Authorization"), "Bearer fixture-session");
    assert.equal(request.init?.body, undefined);
  }
});
