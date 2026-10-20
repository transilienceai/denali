# ADR 0022: GitHub source collection uses immutable, bounded snapshots

## Status

Accepted for the first GitHub-backed repository-to-runtime correlation slice.

## Decision

Source collection is an explicit operation after GitHub App onboarding and validation. It is
not implied by connection health. For every recorded repository, Denali:

1. revalidates the installation account and exact repository ID, node ID, and full name;
2. mints a short-lived installation token restricted to that one repository;
3. resolves the default branch to an immutable commit SHA;
4. reads the Git tree by that SHA; large/truncated recursive responses use a bounded,
   non-recursive walk that prunes excluded directories before descent;
5. downloads only analysis-relevant regular blobs under fixed file and byte limits;
6. analyzes the snapshot without executing repository code; and
7. deletes the temporary source tree and drops the token when the repository run ends.

Analysis-relevant inputs include bounded application source, deployment configuration, MCP
configuration, and direct dependency manifests (`package.json`, `pyproject.toml`, and
`requirements*.txt`). Exact matches to the maintained AI framework and provider-SDK catalog
produce source-declared inventory. When a repository contains at least one such dependency or
another existing AI source signal, Denali emits one AI application for that repository revision,
links it to the repository, and retains the supporting file-and-line evidence.

This Git-only application inventory is deliberately labeled `declared`, with deployment and
runtime status `not_observed`. It does not require a cloud connection, but it also does not claim
that the application is deployed, running, reachable, approved, or safe. Cloud collection remains
the independent evidence required for code-to-cloud proof and runtime conclusions. A dependency
that is not in the high-confidence AI catalog remains ordinary software inventory and does not
create an AI application.

The persisted source locator is `github://repositories/{id}/commits/{sha}`. Temporary paths,
installation tokens, and raw source blobs are not stored. Existing repository inventory,
repository-posture, and code-to-cloud connectors receive explicit remote snapshot metadata so
their evidence cannot accidentally claim a local checkout.

## Correlation and observability

The code-to-cloud connector still requires an exact join between a literal deployment
identifier in supported IaC and an independently observed cloud workload identifier. A proven
candidate emits a `deployed_by` relationship at confidence 1.0. Unmatched and ambiguous
candidates emit no relationship.

Every declaration receives one structured disposition: `proven`, `ambiguous`, or `unmatched`.
The latest source-collection coverage and analysis coverage are queryable independently, so a
failed download, partial static analysis, zero declarations, and zero proven deployments do
not collapse into the same state.

## Safety limits

Collection bounds relevant tree traversal at 20,000 entries, analysis selections at 2,000
files, individual blobs at 2 MB, and aggregate selected content at 25 MB. The fallback walk
also has a fixed tree-request bound; hitting any bound remains explicit incomplete coverage.
Symlinks, submodules, excluded dependency/build/test trees, hidden directories, and irrelevant
file types are not materialized. An incomplete traversal is never complete coverage.

## Current limits

- The shared identity matcher is provider-neutral, but source and workload adapters currently
  support only the existing literal AWS CDK Lambda and ECS rules.
- The source revision is analysis context until an independently observed deployed artifact
  attests that revision.
- Git-only estate discovery covers high-confidence direct dependency and source declarations; it
  does not yet resolve transitive lockfile dependencies or prove that declared code is reachable.
- GitHub Enterprise Server and repository lifecycle reconciliation remain deferred.

## Durable resumable collection

Hosted GitHub collection uses one PostgreSQL job across bounded slices of at most five
repositories. Each repository receives its own bounded request budget rather than a
connection-wide fair-share sample. Completed repository results and the current repository's
immutable commit are checkpointed; raw files and installation tokens are never persisted.
An interrupted repository is re-read at that pinned revision, and completed repositories are
not re-read when the worker resumes. Every slice rechecks installation/repository identity.
Changing the saved installation, account, scopes or repository boundary rejects the checkpoint;
it never expands coverage to newly available repositories.

The worker's monotonically increasing claim generation fences checkpoint updates, terminal
results and every evidence-write transaction. Its lease outlives the Modal hard timeout.
Normal continuation is durably queued before dispatch. A periodic identifier-only reconciler
recovers lost dispatch acknowledgements and expired leases. Provider quota pauses persist a
bounded next-attempt time instead of sleeping inside a worker or claiming terminal partial
coverage. Consecutive worker failures are bounded separately from successful continuations.
Repeated non-quota interruptions of the same repository are also bounded and retain an explicit
partial outcome. A resumable run has a 48-hour durable lifetime; expiry preserves processed
counts and marks the remaining selection unprocessed, not complete. Request counters describe
the most recent slice, with a separate per-repository request limit.

The browser presents processed/queued repository counts and quota pauses separately from the
previous terminal result. Existing collect, job polling, results, permissions and connection
configuration contracts are unchanged. Validation remains independent of collection. File/byte
bounds and unsupported static analysis can still produce honest terminal partial coverage;
resumability does not make those results complete or prove deployment/runtime state.
The public CLI/MCP job receipt remains a bounded job-state projection; repository progress is
a private authenticated browser projection, never the checkpoint itself. Acceptance means the
job is durably queued even when immediate dispatch acknowledgement is unavailable. Local Compose
without a Modal dispatcher retains its existing single-run bounded collection path; it does not
depend on the hosted reconciler.
