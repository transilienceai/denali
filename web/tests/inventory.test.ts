import assert from "node:assert/strict";
import test from "node:test";

import {
  inventoryCategory,
  inventoryCategoryCount,
  inventoryCategoryForKind,
  inventoryKinds,
} from "../src/inventory.ts";

test("inventory kinds are assigned to one customer-facing category", () => {
  assert.equal(inventoryCategoryForKind("ai_agent"), "ai");
  assert.equal(inventoryCategoryForKind("identity"), "supporting");
  assert.equal(inventoryCategoryForKind("software_component"), "components");
  assert.equal(inventoryCategoryForKind("future_kind"), undefined);
});

test("invalid or absent categories fall back to AI resources", () => {
  assert.equal(inventoryCategory(undefined), "ai");
  assert.equal(inventoryCategory("all"), "ai");
  assert.equal(inventoryCategory("components"), "components");
});

test("category counts and available kinds use complete summary counts", () => {
  const byKind = {
    ai_agent: 2,
    ai_workload: 3,
    identity: 4,
    software_component: 365,
  };
  assert.equal(inventoryCategoryCount(byKind, "ai"), 5);
  assert.equal(inventoryCategoryCount(byKind, "supporting"), 4);
  assert.equal(inventoryCategoryCount(byKind, "components"), 365);
  assert.deepEqual(inventoryKinds(byKind, "ai"), ["ai_agent", "ai_workload"]);
});
