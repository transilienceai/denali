import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const tokens = readFileSync(new URL("../src/design-tokens.css", import.meta.url), "utf8");
const styles = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");
const index = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const favicon = readFileSync(new URL("../public/favicon.ico", import.meta.url));

test("vendors the canonical Transilience role-token snapshot for plain CSS", () => {
  assert.match(tokens, /Snapshot digest: d0a557b38a98/);
  assert.match(tokens, /--color-role-surface-page-default:/);
  assert.match(tokens, /--color-role-surface-action-default:/);
  assert.match(tokens, /:root\.dark/);
  assert.match(tokens, /@media \(prefers-color-scheme: dark\)/);
  assert.match(tokens, /@media \(max-width: 767px\)/);
  assert.doesNotMatch(tokens, /(^|\n)\s*@(theme|utility)\b/);
});

test("Denali foundations consume mapped tokens and Inter", () => {
  assert.match(styles, /^@import "\.\/design-tokens\.css";/);
  assert.match(styles, /font-family: "Inter", system-ui, sans-serif/);
  assert.match(styles, /--ink: var\(--color-role-text-content-heading\)/);
  assert.match(styles, /--panel: var\(--color-role-surface-container-default\)/);
  assert.match(styles, /--coral: var\(--color-role-surface-action-default\)/);
  assert.match(styles, /--denali-brand-primary: #895bf7/);
  assert.match(styles, /--color-role-foreground-brand: var\(--denali-brand-primary\)/);
  assert.match(styles, /--app-sidebar-fg-active: var\(--color-role-foreground-accent\)/);
  assert.doesNotMatch(styles, /DM Sans|Manrope|IBM Plex Sans/);
});

test("ships Denali's favicon from the public root", () => {
  assert.match(index, /<link rel="icon" href="\/favicon\.ico" sizes="any" \/>/);
  assert.ok(favicon.byteLength > 0);
});
