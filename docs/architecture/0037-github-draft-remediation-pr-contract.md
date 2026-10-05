# ADR 0037: Opt-in GitHub draft remediation PR capability

Date: 2026-10-05

Status: proposed; **contract only, not implemented or enabled**

## Decision and boundary

The first customer-resource write exposed through Denali's browser/API/CLI/MCP
surfaces will be **create a draft remediation pull request** for a supported,
evidence-linked finding in one explicitly selected GitHub repository. Denali
owns the proposed change, approval, execution, and outcome. Transilience
Platform owns the shared connection and issues a short-lived, repository-bound
GitHub installation token only to Denali's server-side worker. CLI/MCP call the
same Denali-owned capability; they do not receive GitHub credentials or a
general-purpose provider API proxy.

This is not permission to edit arbitrary files, push a default branch, merge a
PR, trigger a workflow, change repository settings, or mutate AWS resources.
Only deterministic, reviewed remediation templates may produce a patch. The
first eligible finding type and template must be selected and tested in a
separate implementation PR; an unsupported finding fails closed. A prompt or
model response is never executable patch authority.

The existing shared GitHub App and Denali-native GitHub connector remain
read-only. The shared App currently requires exactly
`metadata:read`, `contents:read`, and `actions:read` and rejects installations
with additional permissions. Raising its permission level in place would
break that validation and surprise current installations. Instead, use a
**separate write GitHub App**, independently installed and explicitly opted in
by each organization for selected repository IDs. It requests only
`metadata:read`, `contents:write`, and `pull_requests:write`. It does not request
`workflows:write`, Actions write, administration, or organization permissions.
The write App must not be a bypass actor in the target repository's rulesets;
repository rules must require review before any eventual merge. A repository
without that policy is ineligible, even though this capability creates only
draft PRs. Installation or permission changes require a new validation and
explicit organization consent. Existing read connections are not silently
upgraded or made eligible for writes.

## Capability contract (proposed v1)

The paths below describe intended operations, **not currently deployed APIs**.
The actual public and internal route names, schemas, and version are fixed in
the implementation PR and pinned by Platform's capability adapter. No raw
GitHub URL, HTTP method, arbitrary patch, tenant ID, or token is accepted from
the caller.

| Operation | Input and effect |
| --- | --- |
| `POST /v1/findings/{finding_id}/remediations/github-draft-pr/preview` | Read-only. Resolve the finding's exact repository ID, default branch, evidence location, template version, proposed files and unified diff. Return a short-lived `preview_id`, `base_sha`, `patch_sha256`, risk notes, and expiry. No GitHub write token is minted. |
| `POST /v1/findings/{finding_id}/remediations/github-draft-pr/requests` | Submit that exact preview and required `Idempotency-Key`, justification, and target connection ID for approval. Persist a tenant-scoped request and immutable patch hash; no provider mutation. |
| `PATCH /v1/remediations/github-draft-pr/{request_id}/review` | A different current organization admin approves or rejects the immutable request. Self-approval and expired/stale previews fail. This records approval only. |
| Internal durable executor | After approval, recheck every authorization and precondition, mint one selected-repository write token, create a bot-owned non-default branch, commit the exact reviewed patch, and open a **draft** PR against the recorded base branch. Return PR URL and GitHub IDs. Never merge or enable auto-merge. |
| `POST /v1/remediations/github-draft-pr/{request_id}/cancel` | If still open and unmerged, close only the bot-created draft PR after authorization; retain the branch and audit trail for safe recovery. Do not delete a branch or rewrite customer history automatically. |

Preview and execution require a live connection, a selected repository identity
(immutable GitHub numeric ID), a supported finding-to-code link, a path and
template allowlist, and an exact default-branch SHA. Reject workflow files,
secrets, binary files, symlinks, submodules, generated/vendor trees, and paths
outside the reviewed template. Bound file count, patch size, and preview age.
Before writing, compare the current default-branch SHA, file/blob SHAs,
finding state, template version, selected repository list, installation
permissions, approval, and org membership against the request snapshot.
Any drift returns `409` and requires a fresh preview and approval; a missing
provider or membership check returns `503`, not access.

Use a dedicated OAuth/M2M write purpose (for example
`denali:github-remediation:write`) in addition to current membership checks;
do not infer customer-cloud authority from the existing `denali:write` record
scope. Only current organization admins may request or approve. The executor
accepts a durable approved request ID, never an untrusted user-supplied patch.
The Platform entitlement must independently allow that organization, Denali
app, selected connection, repository ID, and `github.draft_pr` scope before a
token is issued. The token is narrowed to **one repository ID** and only the
three stated permissions, is short-lived, never returned to a browser/CLI/MCP,
and is not persisted. Revocation/disable stops new leases immediately.

## Idempotency, audit, and recovery

Persist the request, actor, reviewer, org/tenant, finding, connection,
repository ID, base SHA, template version, patch hash, approval, execution
state, timestamps, GitHub branch/commit/PR IDs, and sanitized failure code.
Never log the installation token, source secrets, or raw private code blobs.
The client `Idempotency-Key` is unique per org + operation and bound to the
canonical request hash: same key and body returns the recorded result;
different body returns `409`. The worker uses a stable branch name and PR
marker derived from the durable request ID. After an ambiguous timeout it
looks up that exact branch and PR before retrying, so it cannot create two PRs.
Provider writes and database commits are not atomic; record each completed
external step and reconcile on retry. A failed PR creation leaves a visible,
audited branch for retry or authorized cancellation, not a blind deletion.

"Rollback" for this first action means closing the draft PR while preserving
its branch and evidence. Since this action never touches the default branch,
no production code is reverted. If a human edits or merges the PR, Denali
must not automatically delete or revert anything; mark the request as needing
manual resolution. Every attempt and state transition is auditable and
rate-limited; a per-org/per-connection kill switch disables execution without
removing existing read access.

## Build and release gates

1. Add a separate write-App installation/entitlement model in Platform and a
   Denali-owned typed preview/request/review/executor contract. Do not alter
   existing read-App validation or connector credentials.
2. Implement one deterministic finding-specific patch template, a durable
   worker, server-side token handling, and tests for no opt-in, wrong org,
   non-admin, self-approval, replay, permission drift, stale SHA, forbidden
   path, partial GitHub success, disabled connection, and cancellation.
3. Exercise against a dedicated test repository and test App; validate draft
   status, base branch unchanged, repo selection, duplicate-call behavior,
   audit completeness, and safe failure recovery. Have security review the
   exact patch template and GitHub App grant.
4. Roll out behind a default-off feature flag to one named production org and
   selected repository only after that org explicitly installs the write App.
   Add an external CLI/MCP acceptance test before wider availability.

The current production MCP receiver exposes Denali-record writes only; it
does **not** provide this customer-cloud capability. The existing read-only
GitHub connection continues to work throughout the rollout. Future AWS or
additional GitHub writes need their own named contracts and provider grants;
`all API writes` is not a safe permission category.

## Provider references

- [GitHub App installation tokens can be restricted to repositories and permissions](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
- [Create a pull request requires Pull requests write](https://docs.github.com/en/rest/pulls/pulls#create-a-pull-request)
- [Create or update repository contents requires Contents write; workflow files need additional permission](https://docs.github.com/en/rest/repos/contents#create-or-update-file-contents)
