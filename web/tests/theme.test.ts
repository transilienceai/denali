import assert from "node:assert/strict";
import test from "node:test";

import { nextTheme, resolveTheme, THEME_STORAGE_KEY } from "../src/theme.ts";

test("stored theme wins over the operating-system preference", () => {
  assert.equal(resolveTheme("light", true), "light");
  assert.equal(resolveTheme("dark", false), "dark");
});

test("first visit follows the operating-system preference", () => {
  assert.equal(resolveTheme(null, true), "dark");
  assert.equal(resolveTheme(null, false), "light");
  assert.equal(resolveTheme("unsupported", true), "dark");
});

test("theme toggle is reversible and uses the stable storage key", () => {
  assert.equal(nextTheme("light"), "dark");
  assert.equal(nextTheme("dark"), "light");
  assert.equal(THEME_STORAGE_KEY, "denali.theme");
});
