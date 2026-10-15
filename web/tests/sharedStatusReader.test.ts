import assert from "node:assert/strict";
import test from "node:test";
import { createSharedStatusReader } from "../src/sharedConnectionAdapter.ts";

test("focus and timer refreshes share the pending request", async () => {
  let complete!: (value: string) => void;
  let requests = 0;
  const accepted: string[] = [];
  const reader = createSharedStatusReader(() => {
    requests += 1;
    return new Promise<string>((resolve) => { complete = resolve; });
  }, (value) => accepted.push(value), () => assert.fail("unexpected failure"));
  const first = reader.refresh();
  const second = reader.refresh();
  assert.equal(first, second);
  await Promise.resolve();
  assert.equal(requests, 1);
  complete("running");
  await first;
  assert.deepEqual(accepted, ["running"]);
});

test("selection or organization changes discard a delayed status response", async () => {
  let complete!: (value: string) => void;
  const accepted: string[] = [];
  const old = createSharedStatusReader(() => new Promise<string>((resolve) => { complete = resolve; }),
    (value) => accepted.push(value), () => assert.fail("unexpected failure"));
  const pending = old.refresh();
  await Promise.resolve();
  old.stop();
  const current = createSharedStatusReader(async () => "new organization", (value) => accepted.push(value),
    () => assert.fail("unexpected failure"));
  await current.refresh();
  complete("old organization");
  await pending;
  await old.refresh();
  assert.deepEqual(accepted, ["new organization"]);
});

test("an abandoned error cannot replace the current selection's status", async () => {
  let fail!: (cause: Error) => void;
  const errors: unknown[] = [];
  const old = createSharedStatusReader(() => new Promise<never>((_, reject) => { fail = reject; }),
    () => assert.fail("unexpected result"), (cause) => errors.push(cause));
  const pending = old.refresh();
  await Promise.resolve();
  old.stop();
  fail(new Error("old request failed"));
  await pending;
  assert.deepEqual(errors, []);
});

test("a failed request permits an explicit retry", async () => {
  let requests = 0;
  const accepted: string[] = [];
  const errors: unknown[] = [];
  const reader = createSharedStatusReader(async () => {
    requests += 1;
    if (requests === 1) throw new Error("temporarily unavailable");
    return "healthy";
  }, (value) => accepted.push(value), (cause) => errors.push(cause));
  await reader.refresh();
  await reader.refresh();
  assert.equal(errors.length, 1);
  assert.deepEqual(accepted, ["healthy"]);
});
