import type { Connection, GitHubSourceCollection } from "./types";

function count(value: number | undefined) {
  return Number.isFinite(value) ? Math.max(0, Math.floor(value!)) : 0;
}

export function githubSourceCollectionCounts(result: Pick<GitHubSourceCollection, "repository_count" | "completed_repository_count" | "failed_count" | "partial_count">) {
  const total = count(result.repository_count);
  // Legacy terminal results processed the entire boundary in one worker run.
  const processed = Math.min(total, count(result.completed_repository_count ?? total));
  const failed = Math.min(processed, count(result.failed_count));
  const partial = Math.min(processed - failed, count(result.partial_count));
  return { processed, total, failed, partial, complete: processed - failed - partial, remaining: total - processed };
}

export function githubSourceCollectionProgress(connection: Connection) {
  if (connection.provider !== "github" || connection.source_collection_state !== "running") return null;
  const progress = connection.source_collection_progress;
  const total = progress ? count(progress.repository_count) : connection.configuration.repositories?.length ?? 0;
  const counts = githubSourceCollectionCounts({ repository_count: total, completed_repository_count: progress?.completed_repository_count ?? 0, failed_count: progress?.failed_count ?? 0, partial_count: progress?.partial_count ?? 0 });
  const { processed, remaining } = counts;
  const retained = Math.min(processed, count(progress?.retained_repository_count));
  const retryAfter = count(progress?.retry_after_seconds);
  const waiting = retryAfter > 0;
  const finalizing = total > 0 && remaining === 0;
  const title = waiting ? "Waiting for GitHub quota" : finalizing ? "Finalizing GitHub source collection" : "GitHub source collection is continuing";
  const summary = retained > 0 ? `${processed - retained} of ${total - retained} affected repositories retried` : total > 0 ? `${processed} of ${total} repositories processed` : "Preparing the saved repository selection";
  const queue = total > 0 ? `${remaining} ${remaining === 1 ? "repository remains" : "repositories remain"} queued.` : "Repository progress will be available after the first batch.";
  const cooldown = retryAfter < 60 ? `${retryAfter} seconds` : `${Math.ceil(retryAfter / 60)} minutes`;
  const detail = waiting
    ? `${queue} The next attempt is eligible in about ${cooldown} at the last update. Denali resumes automatically after the provider cooldown; do not start another collection.`
    : finalizing
      ? "Every selected repository has a recorded outcome. Denali is finalizing the durable run; collection is not complete yet."
      : `${queue} Denali processes the saved selection in resumable batches. Progress refreshes automatically, and it is safe to leave and return.`;
  const retryDetail = retained > 0 ? `${retained} earlier complete results are retained without new provider reads or refreshed timestamps. ${detail}` : detail;
  return { title, summary, detail: retryDetail, ...counts, waiting, updatedAt: progress?.updated_at ?? null };
}
