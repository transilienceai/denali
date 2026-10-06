export function sharedGithubNotEnabled(error: unknown): boolean {
  return error instanceof Error && "status" in error && error.status === 404;
}

export function verifiedInstallUrl(value: string): string {
  const url = new URL(value);
  if (value.length > 2048 || url.protocol !== "https:" || url.host !== "github.com" ||
      url.username || url.password || url.hash || !/^\/apps\/[a-z0-9-]+\/installations\/new$/.test(url.pathname)) {
    throw new Error("GitHub setup link is invalid");
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
