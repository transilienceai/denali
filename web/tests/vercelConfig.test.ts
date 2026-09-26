import assert from "node:assert/strict";
import test from "node:test";

import { config } from "../vercel.mjs";

test("Vercel routing preserves API and platform-owned routes before the SPA fallback", () => {
  assert.equal(config.rewrites?.[0]?.source, "/api/:path*");
  assert.equal(config.rewrites?.[1]?.source, "/:path((?!_vercel/).*)");
  assert.equal(config.rewrites?.[1]?.destination, "/index.html");
  assert.equal(
    config.rewrites?.some((rewrite) => rewrite.source === "/:path*"),
    false,
  );
});
