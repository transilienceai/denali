import assert from "node:assert/strict";
import test from "node:test";
import {
  AI_APPLICATION_DISCOVERY_LABEL,
  PAGE_PATHS,
  closeDrawerTransition,
  drawerTabTransition,
  drawerTabs,
  inventoryQuery,
  navigationFromUrl,
  navigationUrl,
  openDrawerTransition,
  queryWith,
  withoutDrawer,
  type Page,
} from "../src/navigation.ts";

test("AI application discovery uses precise product language without breaking its deep link", () => {
  assert.equal(AI_APPLICATION_DISCOVERY_LABEL, "AI application discovery");
  assert.equal(PAGE_PATHS.shadowAi, "/shadow-ai");
});

test("inventory navigation accepts resource kinds but never serializes click events", () => {
  assert.equal(navigationUrl("inventory", inventoryQuery("ai_workload")), "/inventory?kind=ai_workload");
  assert.equal(navigationUrl("inventory", inventoryQuery("all")), "/inventory");
  assert.equal(
    navigationUrl("inventory", inventoryQuery({ type: "click", currentTarget: {} })),
    "/inventory",
  );
});

test("every product page has a refresh-safe canonical path", () => {
  for (const [page, path] of Object.entries(PAGE_PATHS)) {
    assert.equal(navigationFromUrl(`https://denali.test${path}`).page, page);
    assert.equal(navigationFromUrl(`https://denali.test${path}/`).page, page);
    assert.equal(navigationUrl(page as Page), path);
  }
  assert.equal(navigationFromUrl("https://denali.test/not-a-route").page, "dashboard");
});

test("filters, selected records, drawers, and tabs survive a URL round trip", () => {
  const url = navigationUrl("issues", {
    q: "public model",
    severity: "critical",
    state: "all",
    drawer: "issue",
    id: "issue:123/abc",
    tab: "evidence",
  });
  assert.equal(
    url,
    "/issues?q=public+model&severity=critical&state=all&drawer=issue&id=issue%3A123%2Fabc&tab=evidence",
  );
  assert.deepEqual(navigationFromUrl(`https://denali.test${url}`), {
    page: "issues",
    query: {
      q: "public model",
      severity: "critical",
      state: "all",
      drawer: "issue",
      id: "issue:123/abc",
      tab: "evidence",
    },
    drawer: { kind: "issue", id: "issue:123/abc", tab: "evidence" },
  });
});

test("invalid overlay parameters are removed or normalized", () => {
  assert.deepEqual(
    navigationFromUrl("https://denali.test/inventory?kind=ai_model&drawer=nope&id=42&tab=evil"),
    { page: "inventory", query: { kind: "ai_model" }, drawer: null },
  );
  assert.deepEqual(
    navigationFromUrl("https://denali.test/inventory?drawer=asset&id=42&tab=history"),
    {
      page: "inventory",
      query: { drawer: "asset", id: "42" },
      drawer: { kind: "asset", id: "42", tab: "overview" },
    },
  );
  assert.deepEqual(drawerTabs("finding"), ["overview", "evidence", "history"]);
});

test("provider callbacks always return to the selected connection", () => {
  assert.equal(
    navigationFromUrl("https://denali.test/?github_setup=succeeded&connection_id=abc").page,
    "connections",
  );
  assert.equal(
    navigationFromUrl("https://denali.test/?admin_consent=true&state=abc").page,
    "connections",
  );
});

test("query updates preserve unrelated state and drawer removal preserves filters", () => {
  const query = { q: "agent", severity: "high", drawer: "finding", id: "f-1", tab: "history" };
  assert.deepEqual(queryWith(query, { q: "", state: "open" }), {
    severity: "high",
    drawer: "finding",
    id: "f-1",
    tab: "history",
    state: "open",
  });
  assert.deepEqual(withoutDrawer(query), { q: "agent", severity: "high" });
});

test("overlay history supports Back through tabs and Close to the parent", () => {
  const list = navigationFromUrl("https://denali.test/issues?severity=high");
  const opened = openDrawerTransition(list, { overlayDepth: 0 }, "issue", "issue-1");
  assert.equal(opened.mode, "push");
  assert.deepEqual(opened.state, {
    overlayDepth: 1,
    overlayParent: "/issues?severity=high",
  });

  const detail = navigationFromUrl(`https://denali.test${navigationUrl(opened.page, opened.query)}`);
  const tabbed = drawerTabTransition(detail, opened.state, "evidence");
  assert.ok(tabbed);
  assert.equal(tabbed.mode, "push");
  assert.equal(tabbed.state.overlayDepth, 2);
  assert.equal(tabbed.query.tab, "evidence");
  assert.deepEqual(closeDrawerTransition(detail, tabbed.state), { delta: -2 });
});

test("a pasted deep link closes in place without navigating outside Denali", () => {
  const direct = navigationFromUrl(
    "https://denali.test/runtime-activity?drawer=activity&id=event-1&tab=evidence",
  );
  const changedTab = drawerTabTransition(direct, null, "overview");
  assert.ok(changedTab);
  assert.equal(changedTab.mode, "replace");
  assert.equal(changedTab.state.overlayDepth, 0);
  assert.deepEqual(closeDrawerTransition(direct, null), {
    page: "runtime",
    query: {},
    mode: "replace",
    state: { overlayDepth: 0 },
  });
});
