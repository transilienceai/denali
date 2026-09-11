const COLLECTION_DETAILS: Record<string, string> = {
  github_permission_denied:
    "GitHub denied this repository read. Reconfigure the App and verify Contents access.",
  github_resource_not_found:
    "GitHub could not find this recorded repository. Reconfigure the App selection.",
  github_rate_limited:
    "GitHub rate-limited collection. Denali retried safely; run collection again later.",
  github_timeout:
    "GitHub did not respond before the bounded timeout. Run collection again.",
  github_upstream_unavailable:
    "GitHub was temporarily unavailable after bounded retries. Run collection again.",
  github_api_request_failed:
    "GitHub source collection failed without a specific safe status. Run collection again; if it repeats, inspect backend logs by connection and job ID.",
  repository_tree_incomplete:
    "GitHub returned an incomplete repository tree, so Denali did not claim complete source coverage.",
  repository_tree_limit_exceeded:
    "The repository tree exceeds the current safe traversal budget.",
  repository_empty:
    "The repository is readable but currently has no source revision to analyze.",
};

export function collectionDiagnostic(detail: string | null | undefined): string | null {
  if (!detail) return null;
  if (detail.startsWith("repository analysis budget selected")) {
    return `Partial source snapshot: ${detail}. Missing evidence was not withdrawn.`;
  }
  return COLLECTION_DETAILS[detail] ?? detail;
}

export function noDeploymentExplanation(
  declarations: number,
  hasCloudCollection: boolean,
): string {
  if (declarations > 0 && !hasCloudCollection) {
    return "Source declarations were found, but no independent cloud inventory is connected. Denali will not manufacture deployment links from source alone.";
  }
  if (declarations > 0) {
    return "Source declarations were evaluated, but none matched an independently observed cloud workload by exact provider-scoped identifiers.";
  }
  return "No safely resolvable deployment declarations are available yet. Review partial repository diagnostics or collect additional source.";
}
