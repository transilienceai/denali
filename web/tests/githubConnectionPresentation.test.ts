import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createElement, type ComponentType, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer, type ViteDevServer } from "vite";
import { githubConnectionPresentation } from "../src/githubConnectionPresentation.ts";

type StepProps = {
  credentialType: string; setupComplete: boolean; preparing: boolean;
  canLaunch: boolean; onPrepare: () => void;
  children?: ReactNode;
};
let server: ViteDevServer;
let Step: ComponentType<StepProps>;

before(async () => {
  // Compile the actual TSX component without opening a browser/server port,
  // loading repository .env files, or calling any provider/backend API.
  server = await createServer({
    root: fileURLToPath(new URL("../", import.meta.url)),
    configFile: false,
    envDir: false,
    appType: "custom",
    server: { middlewareMode: true, ws: false, watch: null },
    optimizeDeps: { noDiscovery: true },
  });
  Step = (await server.ssrLoadModule("/src/GitHubSetupStep.tsx")).GitHubSetupStep;
});
after(async () => { await server?.close(); });

function renderStep(overrides: Partial<StepProps> = {}) {
  return renderToStaticMarkup(createElement(Step, {
    credentialType: "github_app_installation", setupComplete: true,
    preparing: false, canLaunch: true, onPrepare: () => {}, ...overrides,
  }));
}

test("shared copy assigns App ownership and token issuance to Platform", () => {
  const shared = githubConnectionPresentation("platform_shared_github");
  assert.equal(shared.shared, true);
  assert.match(shared.planDetail, /Platform-owned GitHub installation/);
  assert.match(shared.validationDetail, /token from Platform for one recorded repository/);
  assert.match(shared.notValidatedDetail, /^Validate this shared connection/);
  assert.match(shared.setupHint, /detach and re-attach/);
  assert.match(shared.lifecycleDetail, /validation\/job history/);
  assert.match(shared.lifecycleDetail, /preserving the Platform installation and collected evidence/);
  assert.doesNotMatch(JSON.stringify(shared), /Denali mints|Denali’s configured GitHub App/);
});

test("shared component hides native controls even if native launch capability is true", () => {
  const markup = renderStep({
    credentialType: "platform_shared_github", canLaunch: true,
    children: createElement("code", null, "transilienceai/example · ID 42"),
  });
  assert.match(markup, /Platform installation verified/);
  assert.match(markup, /reusable GitHub section above/);
  assert.match(markup, /transilienceai\/example · ID 42/);
  assert.doesNotMatch(markup, /<button|Reconfigure GitHub App|Install \/ configure|private signing key|launch-unavailable/);
});

test("native component preserves install, reconfigure, progress and missing-key states", () => {
  const installed = renderStep();
  assert.match(installed, /Reconfigure GitHub App/);
  assert.doesNotMatch(installed, /<button[^>]*disabled|Platform installation/);
  assert.match(renderStep({ setupComplete: false }), /Install \/ configure GitHub App/);
  const missing = renderStep({ canLaunch: false });
  assert.match(missing, /<button[^>]*disabled/);
  assert.match(missing, /GitHub onboarding requires Denali’s configured GitHub App and private signing key/);
  const preparing = renderStep({ preparing: true });
  assert.match(preparing, /Opening GitHub/);
  assert.match(preparing, /aria-busy="true"[^>]*disabled/);
  const native = githubConnectionPresentation("github_app_installation");
  assert.equal(native.planTitle, "1. Connection plan created");
  assert.match(native.validationDetail, /^Denali mints a separate short-lived installation token/);
});

test("GitHub detail wires credential-specific setup, validation and local lifecycle copy", () => {
  const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  const detail = app.split("function GitHubConnectionDetail(")[1].split("function validationStateRank(")[0];
  assert.match(detail, /githubConnectionPresentation\(connection\.credential_reference\.type\)/);
  assert.match(detail, /GitHubSetupStep credentialType=\{connection\.credential_reference\.type\}/);
  for (const field of ["planTitle", "planDetail", "validationDetail", "notValidatedDetail", "allRepositoriesDetail", "lifecycleDetail"]) {
    assert.ok(detail.includes(`presentation.${field}`));
  }
});
