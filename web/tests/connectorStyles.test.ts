import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, test } from "node:test";
import { JSDOM } from "jsdom";

const styles = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");
const tokens = readFileSync(new URL("../src/design-tokens.css", import.meta.url), "utf8");
const layer = styles.slice(styles.indexOf("/* Connections component layer:"));
const dom = new JSDOM(`<!doctype html><html><head><style></style></head><body>
  <section class="connection-onboarding-wizard">
    <div class="connection-provider-picker"><button class="connection-provider-tab active" aria-pressed="true" id="provider">Microsoft Azure<img class="connection-provider-tab-icon" id="provider-icon" alt=""></button></div>
    <div class="connection-wizard-adapter"><section class="shared-aws-pilot">
      <form class="shared-aws-pilot-form connector-form" id="form">
        <label class="connector-field">Name<input id="name"></label>
        <label class="connector-field connector-field-wide" id="wide">Subscriptions<textarea id="textarea"></textarea></label>
        <fieldset><legend>Legacy evidence planes</legend><label id="legacy-choice"><input type="checkbox" id="legacy-checkbox">AI services</label></fieldset>
        <fieldset class="connector-evidence-picker"><legend>Selected evidence</legend><div class="connector-choice-grid" id="choices">
          <label class="connector-choice" data-selected="true" id="choice"><input type="checkbox" id="checkbox"><span class="connector-choice-copy"><strong>Foundry runtime activity</strong><small>Metadata-only sessions.</small></span></label>
        </div></fieldset>
        <div class="shared-aws-pilot-detail connector-form">
          <fieldset class="repository-picker" id="repositories"><legend>Repositories</legend>
            <ul class="repository-picker-list" id="repository-list"><li><label class="repository-picker-item shared-github-repository-choice" id="repository"><input type="checkbox" id="repository-checkbox"><span class="connector-choice-copy"><strong>organization/repository</strong></span></label></li></ul>
          </fieldset>
          <details class="connector-access-expander" id="access"><summary>Review access</summary></details>
        </div>
      </form>
    </section></div>
    <div class="connector-loading" id="loading"><div class="connector-skeleton"><span></span><span></span><div><span></span><span></span></div></div></div>
    <div class="connector-loading compact" id="compact-loading"></div>
  </section>
  <form class="connection-create"><fieldset class="connection-create-lock"><fieldset class="connector-evidence-picker" id="native-evidence"><legend>Native evidence</legend><div class="connector-choice-grid"><label class="connector-choice" id="native-choice"><input type="checkbox" id="native-checkbox"><span class="connector-choice-copy"><strong>Read-only metadata</strong></span></label></div></fieldset></fieldset></form>
  <label id="unrelated-label">Profile preference<input type="checkbox" id="unrelated-checkbox"></label><textarea id="unrelated-textarea"></textarea>
  <div class="read-only-detail"><fieldset class="connection-detail-access" disabled id="readonly-access"><div class="connection-launch-actions"><a href="https://example.invalid/setup" id="readonly-setup">Provider setup</a></div><details><summary id="readonly-summary">Read evidence</summary><p>Evidence remains visible.</p></details><a href="https://example.invalid/docs" id="readonly-docs">Documentation</a></fieldset></div>
</body></html>`);
dom.window.document.querySelector("style")!.textContent = styles.replace(/^@import.*$/gm, "");
after(() => dom.window.close());
const computed = (id: string) => dom.window.getComputedStyle(dom.window.document.getElementById(id)!);

test("legacy shared Azure choices pair each checkbox and label without inherited text-input geometry", () => {
  assert.equal(computed("legacy-choice").display, "flex");
  assert.equal(computed("legacy-choice").flexDirection, "row");
  assert.equal(computed("legacy-choice").minHeight, "44px");
  for (const id of ["legacy-checkbox", "checkbox", "repository-checkbox", "native-checkbox"]) {
    const input = computed(id);
    assert.equal(input.width, "16px");
    assert.equal(input.height, "16px");
    assert.equal(input.minHeight, "16px");
    assert.equal(input.maxHeight, "16px");
    assert.equal(input.padding, "0px");
    assert.equal(input.flexShrink, "0");
  }
});

test("native and shared evidence cards have two desktop columns and full-width long fields", () => {
  assert.equal(computed("choice").display, "flex");
  assert.equal(computed("choice").flexDirection, "row");
  assert.equal(computed("choices").gridTemplateColumns, "repeat(2, minmax(0, 1fr))");
  assert.equal(computed("form").gridTemplateColumns, "repeat(2, minmax(0, 1fr))");
  assert.equal(computed("wide").gridColumn, "1 / -1");
  assert.equal(computed("textarea").minHeight, "86px");
  assert.equal(computed("textarea").maxHeight, "260px");
  assert.equal(computed("native-choice").display, "flex");
  assert.equal(computed("native-evidence").padding, "14px");
});

test("repository review stays full-width, horizontally paired and bounded rather than growing the page", () => {
  assert.equal(computed("repositories").gridColumn, "1 / -1");
  assert.equal(computed("repositories").padding, "0px");
  assert.equal(computed("repository-list").maxHeight, "352px");
  assert.equal(computed("repository-list").overflowY, "auto");
  assert.equal(computed("repository").display, "flex");
  assert.equal(computed("repository").margin, "0px");
  assert.equal(computed("access").gridColumn, "1 / -1");
});

test("the compact component layer does not restyle unrelated form fields", () => {
  assert.notEqual(computed("unrelated-label").display, "flex");
  assert.notEqual(computed("unrelated-checkbox").minHeight, "16px");
  assert.notEqual(computed("unrelated-textarea").minHeight, "86px");
  assert.doesNotMatch(layer, /(?:^|\n)(?:input|button|label|textarea|fieldset|body|html|:root)\s*[{,]/);
});

test("read-only detail hides setup links but keeps evidence disclosures and documentation usable", () => {
  assert.equal(computed("readonly-access").minWidth,"0px");
  assert.equal(computed("readonly-access").padding,"0px");
  assert.equal(computed("readonly-setup").display,"none");
  assert.notEqual(computed("readonly-summary").pointerEvents,"none");
  assert.notEqual(computed("readonly-docs").pointerEvents,"none");
  assert.notEqual(computed("readonly-docs").display,"none");
});

test("provider selection keeps a readable keyboard target and loading reserves bounded space", () => {
  assert.equal(computed("provider").minHeight, "44px");
  assert.equal(computed("provider-icon").order, "-1");
  assert.equal(computed("provider-icon").width, "20px");
  assert.equal(computed("loading").minHeight, "176px");
  assert.equal(computed("compact-loading").minHeight, "100px");
  assert.match(layer, /:focus-visible\s*\{\s*outline: 2px solid var\(--color-role-foreground-accent\)/);
});

test("mobile and reduced-motion behavior are explicit in the scoped component layer", () => {
  const sheet = dom.window.document.querySelector("style")!.sheet!;
  const media = [...sheet.cssRules].filter((rule): rule is CSSMediaRule => "conditionText" in rule);
  const mobile = media.filter((rule) => rule.conditionText === "(max-width: 780px)").map((rule) => rule.cssText).join("\n");
  assert.match(mobile, /\.connector-choice-grid[\s\S]*?grid-template-columns: minmax\(0, 1fr\)/);
  assert.match(mobile, /\.repository-picker-list[^}]*max-height: 288px/);
  const reduced = media.filter((rule) => rule.conditionText === "(prefers-reduced-motion: reduce)").map((rule) => rule.cssText).join("\n");
  assert.match(reduced, /\.connector-loading \*[\s\S]*?animation: none;[\s\S]*?transition: none;/);
});

function variables(block: string) {
  return Object.fromEntries([...block.matchAll(/(--[\w-]+):\s*([^;]+);/g)].map((match) => [match[1]!, match[2]!.trim()]));
}
function color(name: string, values: Record<string, string>): string {
  let value = values[name]!;
  for (let depth = 0; depth < 16; depth += 1) {
    const reference = /^var\((--[\w-]+)\)$/.exec(value);
    if (!reference) return value;
    value = values[reference[1]!]!;
  }
  throw new Error(`Unresolved theme color: ${name}`);
}
function luminance(hex: string) {
  assert.match(hex, /^#[\da-f]{6}$/i);
  const channels = [1, 3, 5].map((start) => parseInt(hex.slice(start, start + 2), 16) / 255)
    .map((value) => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4);
  return channels[0]! * .2126 + channels[1]! * .7152 + channels[2]! * .0722;
}
function contrast(foreground: string, background: string, values: Record<string, string>) {
  const colors = [luminance(color(foreground, values)), luminance(color(background, values))].sort((a, b) => b - a);
  return (colors[0]! + .05) / (colors[1]! + .05);
}

test("connection copy, selected evidence, primary actions and focus use contrasting light/dark role tokens", () => {
  const light = variables(tokens.match(/:root\s*\{([\s\S]*?)\n\}/)![1]!);
  const dark = { ...light, ...variables(tokens.match(/:root\.dark,\s*html\.dark\s*\{([\s\S]*?)\n\}/)![1]!) };
  for (const [mode, values] of [["light", light], ["dark", dark]] as const) {
    for (const foreground of ["--color-role-text-content-body", "--color-role-text-content-subtle"]) {
      for (const background of ["--color-role-surface-component-default", "--color-role-surface-component-selected"]) {
        assert.ok(contrast(foreground, background, values) >= 4.5, `${mode}: ${foreground} on ${background}`);
      }
    }
    assert.ok(contrast("--color-role-foreground-on-color", "--color-role-surface-action-default", values) >= 4.5, `${mode}: primary action`);
    assert.ok(contrast("--color-role-foreground-accent", "--color-role-surface-component-default", values) >= 3, `${mode}: visible focus`);
  }
});
