import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { parseSharedGcpProjects, sharedGcpCanRetry, sharedGcpNotEnabled } from "../src/sharedGcpOnboarding.ts";

test("shared GCP preserves exact IDs and numbers and canonicalizes retry identity", () => {
  assert.deepEqual(parseSharedGcpProjects(" zulu-project : 123456789012\nalpha-project:234567890123 "), [
    { id: "alpha-project", number: "234567890123" },
    { id: "zulu-project", number: "123456789012" },
  ]);
});

test("shared GCP rejects empty, broad, duplicate and malformed project selections", () => {
  for (const value of ["", "*:*", "projects/foo:123456", "project-one:1", "project-one:123456:extra",
    "project-one:123456:", "project-one:123456,project-one:234567",
    "project-one:123456,project-two:123456",
    Array.from({ length: 9 }, (_, index) => `project-${index}:12345${index}`).join("\n")]) {
    assert.throws(() => parseSharedGcpProjects(value));
  }
});

test("only an explicit default-off or non-pilot 404 hides shared GCP", () => {
  assert.equal(sharedGcpNotEnabled(Object.assign(new Error("not enabled"), { status: 404 })), true);
  for (const status of [401, 403, 409, 502, 503]) {
    assert.equal(sharedGcpNotEnabled(Object.assign(new Error("failed"), { status })), false);
  }
  assert.equal(sharedGcpNotEnabled(new Error("network error")), false);
});

test("browser GCP lifecycle stays behind relative authenticated API and durable statuses", () => {
  const api = readFileSync(new URL("../src/api.ts", import.meta.url), "utf8");
  const panel = readFileSync(new URL("../src/SharedGcpPilot.tsx", import.meta.url), "utf8");
  assert.match(api, /const API_BASE = "\/api"/);
  for (const suffix of ["setup.sh", "validation", "validate", "use-in-denali", "disable"]) {
    assert.ok(api.includes(`/shared/connections/gcp/\${encodeURIComponent(id)}/${suffix}`));
  }
  assert.match(panel, /creation\.current\.id/);
  assert.match(panel, /status\?\.job_state/);
  assert.match(panel, /No service-account JSON key is needed/);
  assert.match(panel, /window\.confirm/);
  assert.match(panel, /window\.prompt/);
  assert.doesNotMatch(panel, /modal\.run|service_account_key|access_token|credentials\(/);
});

test("failed and stale provision jobs can retry but active leases and disabled plans cannot", () => {
  assert.equal(sharedGcpCanRetry({ retry_available: true }, "needs_setup"), true);
  assert.equal(sharedGcpCanRetry({ retry_available: true }, "needs_validation"), true);
  assert.equal(sharedGcpCanRetry({ retry_available: false }, "needs_setup"), false);
  assert.equal(sharedGcpCanRetry({ retry_available: true }, "disabled"), false);
  assert.equal(sharedGcpCanRetry(null, "needs_setup"), false);
  assert.equal(sharedGcpCanRetry({}, "needs_setup"), false);
});
