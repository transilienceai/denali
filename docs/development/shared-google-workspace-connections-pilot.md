# Shared Google Workspace connections

This default-off browser pilot reuses one admitted Platform Workspace connection
inside its exact Clerk organization. Platform owns the keyless domain-wide
delegation identity, approved customer/domain/admin subject, and provider access.
Denali owns catalog matching, AI application inventory, activity, coverage and
derived findings. Native Workspace users and the separate Shasta bridge retain
their existing operator configuration and execution paths.

The only Google scope is
`https://www.googleapis.com/auth/admin.reports.audit.readonly`. The fixed bundle
is `google_workspace.gemini_activity` (`gemini_in_workspace_apps`) and
`google_workspace.oauth_activity` (`token`). Directory token-management,
Gmail/Drive content, customer credentials and provider writes are outside this
read plan. OAuth applications are observations within the bounded audit window,
not a complete inventory of current grants or automatic security findings.

## Environment and release

Deploy reviewed merged source through each environment's protected workflow.
`DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED` is a public deployment variable with
only literal `true` or `false` accepted; absent means false. Both workflows pass
it to the existing deployment-scoped Modal configuration on every API and worker.
It is not a new named Secret or frontend variable. Preserve the existing core
machine key, exact organization allowlist and environment-matched Platform origin.
Production activation also requires the reviewed production origin/organization
guard. The flag alone cannot admit a customer or grant provider access.

No migration, job kind, Google credential, native `DENALI_GOOGLE_WORKSPACE_*`
change, or additional secret mount is needed. Platform must separately admit the
exact org/customer/domain/admin-subject and operator identity, and entitle the
Denali machine to both read planes. An email suffix or empty successful response
cannot establish that admission. Native Google ADC is never a shared fallback.

## Setup, attachment and evidence

1. An organization admin opens Connections and selects an admitted Workspace
   target from the reusable panel. The server supplies target identity; the browser
   cannot supply another customer, domain, delegated subject, or organization.
2. Register the plan. A repeated unchanged submission keeps the same request ID.
   Review the exact service account, numeric OAuth client ID and sole audit scope.
3. A Workspace super administrator authorizes that client/scope pair in Admin
   Console's domain-wide delegation page. There is no OAuth callback, customer
   JSON key, refresh token, or native Denali authorization checkbox for this plan.
4. Select Validate authorization. Platform probes both read planes and returns
   its committed status. Failed or unavailable planes remain failed/partial.
   Successful empty reports prove callability while observed customer identity
   remains null; they do not manufacture an observed tenant.
5. Attach only a ready, active, healthy plan with the exact complete validated
   bundle and a validation timestamp within 15 minutes. Denali rechecks the pinned
   target/revision and performs fresh tiny reads of both planes before attachment.
   Repeat attachment is idempotent; changed identity or a native UUID collision
   conflicts without rebinding the saved row.
6. Validate the attached Denali connection and collect Workspace evidence. The
   existing PostgreSQL validation/collection jobs and Modal workers reload the
   tenant's server-owned Clerk organization and execute mediated Reports reads.
   Healthy validation queues the first durable collection as before.
7. Read actual inventory, sources coverage, activity and findings through the
   existing browser or CLI/MCP capabilities. Validation and collection have
   separate receipts; a completed job or green badge alone does not prove data.

The adapter retains the native 180-day maximum window and 20,000-record limit.
Shared reads request at most 100 records per page, including when the existing
collector requests 1,000; one-record validation probes remain one record. This
reduces page size rather than truncating the scan: the same opaque cursor and
exact interval continue across pages, and each response is checked against the
actual requested size. Native, unshared Reports reads retain their existing
1,000-record default. An oversized page or any exhausted bound still fails the
affected coverage plane instead of claiming complete or zero-finding coverage.
It fixes the exact interval across pages, allows only two operations, limits
responses to 2 MiB per page and 16 MiB per plane, at most 200 pages and a 1,500-second
overall reports deadline. Invalid/repeated cursors, identity/revision/window
mismatch, malformed/sensitive DTO fields and bounded truncation fail closed.
Provider event order is preserved for source UID stability. Metadata contains
only allowed IDs, event taxonomy and fixed parameters; actor email, IP addresses,
prompts, outputs and raw report objects are rejected. Platform's fixed sanitized
DTOs feed Denali's existing normalizer rather than duplicating business logic.

Workspace RPCs opt into the shared client's bounded streaming JSON path. Its
60-second total budget includes M2M minting, HTTP and parsing; a capped request
pool prevents abandoned SDK calls from creating unlimited work. The machine token
has enough remaining TTL for final broker checks. Redirects, compression, malformed
JSON and oversized bodies fail with sanitized errors. Existing provider callers
retain their original transport path.

Repeated healthy broker validation of unchanged authority refreshes its timestamp
without invalidating attached Denali references. A real target/read-authority
change, failed validation or recovery advances the binding revision; the saved
reference then fails closed. Review the changed target before explicitly retiring
and reattaching a local reference. Do not silently rebind it or delete job history
without approval. Routine Validate in Denali uses the current mediated reference.

## Browser and CLI contract

All six setup/status/attachment routes remain authenticated same-origin
`/api/v1/shared/connections/google-workspace/*` browser workflows. Members may
read; mutations require an organization admin. The feature hides on 404, while
upstream errors remain visible. Native setup completion is rejected for a shared
reference. Local Disable/Delete retires Denali use only; previous evidence remains.
Organization-wide Platform disconnect and removal of the Workspace DWD grant
remain separate administrator actions.

Existing `connections`, `connection-detail`, `connection-validate`,
`connection-collect` with `google_workspace_ai`, both durable job reads, inventory,
activity, coverage and findings retain their public contracts. No new onboarding
MCP tool, typed CLI verb, OAuth login scope or package installation is required.
The paired Platform broker contract is reviewed with this adapter. Denali's
canonical public registry and its existing Platform snapshot are unchanged, so
this internal connector change needs no new public catalog/source pin.

## Acceptance and rollback

Local verification covers two organizations, admin/member/anonymous boundaries,
stale/partial authorization, immutable attachment, no native fallback, real
PostgreSQL tenant rows, duplicate durable workers and sanitized reports. Preserve
native Workspace and Shasta secret dependency checks. Run full Python, PostgreSQL,
Ruff, Modal compilation, frontend and Platform-delivery gates before handoff.

Production acceptance requires admitted setup → exact external authorization →
both Platform probes → attachment → Denali validation → actual collection →
CLI/MCP result reads, plus denial/revocation and local lifecycle checks. Only after
production acceptance replicate the reviewed code to development with isolated
identities, targets and grants, then repeat the same checks. Never copy production
credentials, admission bindings or database settings into development.

Rollback by setting the public flag false and redeploying reviewed source through
the normal workflow. Shared reads then fail closed; existing native identity and
retained evidence remain. This source change alone is not hosted acceptance.
