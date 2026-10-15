export function sharedGithubNotEnabled(error: unknown): boolean {
  return error instanceof Error && "status" in error && error.status === 404;
}

export function verifiedInstallUrl(value: string): string {
  const url = new URL(value);
  if (value.length > 2048 || url.protocol !== "https:" || url.host !== "github.com" ||
      url.username || url.password || url.hash ||
      (!/^\/apps\/[a-z0-9-]+\/installations\/new$/.test(url.pathname) && url.pathname !== "/login/oauth/authorize")) {
    throw new Error("GitHub setup link is invalid");
  }
  if (url.pathname === "/login/oauth/authorize") {
    const params = url.searchParams;
    const keys = ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "allow_signup"];
    const callback = new URL(params.get("redirect_uri") ?? "");
    if ([...params].length !== keys.length || keys.some((key) => params.getAll(key).length !== 1) ||
        !/^[A-Za-z0-9_.-]{1,200}$/.test(params.get("client_id") ?? "") ||
        !/^[A-Za-z0-9_-]{43,128}$/.test(params.get("state") ?? "") ||
        !/^[A-Za-z0-9_-]{43}$/.test(params.get("code_challenge") ?? "") ||
        params.get("code_challenge_method") !== "S256" || params.get("allow_signup") !== "false" ||
        callback.protocol !== "https:" || callback.username || callback.password || callback.port || callback.search || callback.hash ||
        callback.pathname !== "/v1/connections/github/oauth/callback") throw new Error("GitHub authorization link is invalid");
  }
  return url.toString();
}

export function selectedGithubRepositoryIds(selected: readonly number[], available: readonly number[]): number[] {
  if (selected.length < 1 || selected.length > 500 || new Set(selected).size !== selected.length ||
      selected.some((id) => !Number.isSafeInteger(id) || id <= 0 || !available.includes(id))) {
    throw new Error("Select available GitHub repositories");
  }
  return [...selected].sort((left, right) => left - right);
}

export type GithubRepositoryIdentity = {
  id: number | string;
  node_id?: string;
  full_name: string;
  owner_id?: number;
  owner_login?: string;
};

export function sameGithubRepositoryIdentity(left: GithubRepositoryIdentity, right: GithubRepositoryIdentity): boolean {
  return String(left.id) === String(right.id)
    && left.node_id === right.node_id && left.full_name === right.full_name
    && left.owner_id === right.owner_id && left.owner_login === right.owner_login;
}

export function githubRepositoryChanges<T extends GithubRepositoryIdentity>(
  saved: readonly GithubRepositoryIdentity[], available: readonly T[],
) {
  const before = new Map(saved.map((repo) => [String(repo.id), repo]));
  const after = new Map(available.map((repo) => [String(repo.id), repo]));
  return {
    added: available.filter((repo) => !before.has(String(repo.id))),
    removed: saved.filter((repo) => !after.has(String(repo.id))),
    changed: available.filter((repo) => {
      const original = before.get(String(repo.id));
      return !!original && !sameGithubRepositoryIdentity(original, repo);
    }),
  };
}

/** Retain reviewed choices only while their immutable identity still matches. */
export function retainGithubRepositorySelection(
  selected: readonly number[], before: readonly GithubRepositoryIdentity[], after: readonly GithubRepositoryIdentity[],
): number[] {
  const previous = new Map(before.map((repo) => [String(repo.id), repo]));
  const current = new Map(after.map((repo) => [String(repo.id), repo]));
  return [...new Set(selected)].filter((id) => {
    const left = previous.get(String(id));
    const right = current.get(String(id));
    return !!left && !!right && sameGithubRepositoryIdentity(left, right);
  }).sort((left, right) => left - right);
}
