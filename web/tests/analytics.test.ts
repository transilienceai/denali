import assert from "node:assert/strict";
import test from "node:test";
import { sanitizeAnalyticsEvent } from "../src/analytics.ts";

test("analytics retains the route but removes selected resource identifiers", () => {
  assert.deepEqual(
    sanitizeAnalyticsEvent({
      type: "pageview",
      url: "https://denali.transilience.cloud/connections?connection=secret-id&new=1#setup",
    }),
    {
      type: "pageview",
      url: "https://denali.transilience.cloud/connections",
    },
  );
});

test("analytics drops an event when its URL cannot be safely normalized", () => {
  assert.equal(
    sanitizeAnalyticsEvent({ type: "event", url: "not a valid absolute URL" }),
    null,
  );
});
