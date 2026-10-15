import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { githubRepositoryChanges, retainGithubRepositorySelection, selectedGithubRepositoryIds, sharedGithubNotEnabled, verifiedInstallUrl } from "../src/sharedGithubOnboarding.ts";

test("refresh re-reads exact repositories even if installation ID/count stay unchanged", () => {
  const component = readFileSync(new URL("../src/SharedGitHubPilot.tsx", import.meta.url), "utf8");
  assert.match(component, /api\.sharedGithubRepositories\(selected\.id\)/);
  assert.match(component, /\}, \[selected\]\);/);
  assert.doesNotMatch(component, /\[selected\?\.id, selected\?\.availability\]/);
  assert.match(component, /setRepositoryIds\(\[\]\);/);
  assert.match(component, /api\.useSharedGithubInDenali\(selected\.id, ids, scopes\)/);
  assert.match(component, /retainGithubRepositorySelection\(/);
  assert.doesNotMatch(component, /setRepositoryIds\(result\.items/);
});

const repository = { id: 42, node_id: "R_42", full_name: "example/first", owner_id: 7, owner_login: "example", private: true, default_branch: "main" };
const added = { ...repository, id: 43, node_id: "R_43", full_name: "example/second" };

test("refresh preserves reviewed repository identities and never selects additions", () => {
  assert.deepEqual(retainGithubRepositorySelection([42], [repository], [repository, added]), [42]);
  assert.deepEqual(retainGithubRepositorySelection([], [], [repository, added]), []);
  assert.deepEqual(retainGithubRepositorySelection([42, 43], [repository, added], [repository, added]), [42, 43]);
  assert.deepEqual(retainGithubRepositorySelection([42], [repository], [{ ...repository, private: false, default_branch: "trunk" }]), [42]);
});

test("repository removal, replacement, rename, transfer and case drift require review", () => {
  for (const patch of [{ node_id: "R_replacement" }, { full_name: "example/renamed" }, { full_name: "Example/first" }, { owner_id: 8 }, { owner_login: "other-owner" }]) {
    const changed = { ...repository, ...patch };
    assert.deepEqual(retainGithubRepositorySelection([42], [repository], [changed]), []);
    assert.deepEqual(githubRepositoryChanges([repository], [changed]).changed, [changed]);
  }
  const changes = githubRepositoryChanges([repository], [added]);
  assert.deepEqual(changes.added, [added]);
  assert.deepEqual(changes.removed, [repository]);
  assert.deepEqual(changes.changed, []);
  assert.deepEqual(retainGithubRepositorySelection([42], [repository], []), []);
});

test("explicit repository selection is canonical, nonempty and never inherits additions", () => {
  assert.deepEqual(selectedGithubRepositoryIds([43, 42], [42, 43, 44]), [42, 43]);
  assert.deepEqual(selectedGithubRepositoryIds([42], [41, 42, 43]), [42]);
  for (const selected of [[], [42, 42], [0], [-1], [42.5], [Number.MAX_SAFE_INTEGER + 1], [99], Array.from({ length: 501 }, (_, id) => id + 1)]) {
    assert.throws(() => selectedGithubRepositoryIds(selected, [42, 43]));
  }
});

test("shared GitHub installs use the exact GitHub origin and installation path", () => {
  assert.equal(verifiedInstallUrl("https://github.com/apps/transilience-platform/installations/new?state=opaque"), "https://github.com/apps/transilience-platform/installations/new?state=opaque");
  for (const url of ["http://github.com/apps/app/installations/new", "https://github.com.evil/apps/app/installations/new", "https://user:secret@github.com/apps/app/installations/new", "javascript:alert(1)", "https://github.com/apps/app/installations/new#secret"]) assert.throws(() => verifiedInstallUrl(url));
});

test("existing installation verification accepts only the exact GitHub OAuth endpoint", () => {
  const oauth = `https://github.com/login/oauth/authorize?client_id=Iv1.test&redirect_uri=https%3A%2F%2Fplatform.example%2Fv1%2Fconnections%2Fgithub%2Foauth%2Fcallback&state=${"s".repeat(64)}&code_challenge=${"c".repeat(43)}&code_challenge_method=S256&allow_signup=false`;
  assert.equal(verifiedInstallUrl(oauth), oauth);
  for (const url of ["https://github.com/login/oauth/authorize/other", "https://github.com/login/oauth/authorize#fragment", "https://github.com.evil/login/oauth/authorize", "https://user:secret@github.com/login/oauth/authorize", "https://github.com/organizations/example/settings/installations/99"]) assert.throws(() => verifiedInstallUrl(url));
  for (const url of [oauth + "&state=duplicate", oauth.replace("S256", "plain"), oauth.replace("state=" + "s".repeat(64), "state=short"), oauth.replace("allow_signup=false", "allow_signup=true"), oauth.replace("oauth%2Fcallback", "wrong%2Fcallback"), oauth.replace("https%3A%2F%2Fplatform.example", "http%3A%2F%2Fplatform.example")]) assert.throws(() => verifiedInstallUrl(url));
});

test("only default-off and non-pilot 404 hides shared GitHub; errors never choose native", () => {
  assert.equal(sharedGithubNotEnabled(Object.assign(new Error("disabled"), { status: 404 })), true);
  for (const status of [401, 403, 409, 422, 502, 503]) assert.equal(sharedGithubNotEnabled(Object.assign(new Error("failure"), { status })), false);
});
