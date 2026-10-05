# Denali capability receiver

Denali remains the owner of its data and authorization. The Transilience gateway is
an authenticated client of these **internal** routes, not a database reader. The
browser continues to use the existing same-origin `/api/v1/*` routes. This
receiver is opt-in: with both production machine IDs unset, the internal
routes return 404 and existing browser/connector behavior is unchanged.
Partial machine configuration fails startup rather than allowing access.
The gateway calls the direct production Modal API origin
(`https://transilience-denali-prod--denali-production-api.modal.run`) with
the exact `/internal/v1/*` paths below. The browser's Vercel `/api/*` rewrite
is not a server-to-server base URL.

## Request contract

`GET /internal/v1/capabilities/{operation}` accepts exactly one named operation.
Detail operations require `?id=<UUID>`; runtime session detail/export instead require a
64-character lowercase hex session key. Lists accept only their documented Denali
filters, `limit` (1–100), and `offset` (0–100000). Invalid/duplicate/unknown query
parameters return 422. The receiver forwards to the existing tenant-scoped Denali
handler; it never accepts a URL, tenant ID, or arbitrary route from the gateway.
Code-to-cloud deployments and observations default to a 100-item gateway page;
both accept `limit` and `offset` for subsequent pages. Their existing browser
routes retain the unbounded default when those parameters are omitted.

| Area | Read operations |
| --- | --- |
| Context | `context` |
| Connections | `connections`, `connection-detail` (Denali-local status, not Platform connector configuration) |
| Inventory | `inventory-summary`, `assets`, `asset-detail`, `sources-coverage` |
| Findings | `findings-summary`, `findings`, `finding-detail` |
| Vulnerabilities | `vulnerabilities-summary`, `vulnerabilities`, `vulnerability-detail`, `vulnerability-import-status` |
| Issues | `issues-summary`, `issues`, `issue-detail`, `issue-evaluations` |
| Code-to-cloud | `code-to-cloud-deployments`, `code-to-cloud-observations` |
| Activity | `activity-summary`, `activity`, `activity-detail`, `runtime-sessions`, `runtime-session-detail`, `runtime-session-export` |
| Detections | `detections-summary`, `detections`, `detection-detail`, `detection-evaluations` |

The read catalog contains 35 named operations. The exhaustive
[machine-readable public surface map](capability-surface.json) records the 77
explicit public route/method operations, four generated documentation routes,
and all 67 browser client methods at its pinned baseline. It classifies each
operation and records existing or planned capability ownership; it is not a
claim of literal public API parity.

`context` reuses the authenticated organization context. `runtime-session-export`
requires a lowercase 64-character session key as `id`, and returns the native
metadata-only JSON export schema and attachment header. The gateway export is
limited to 100 ordered activities and 2 MiB of serialized JSON. Native
`session.truncated` identifies omitted activities; oversized exports return 413.
The browser retains its existing export limits.

`connections` accepts `limit` (1–100, default 20) and `offset` (0–100000)
and returns a stable ID-ordered page with `has_more`. `connection-detail`
requires `?id=<UUID>`. Both read only the Denali-local connection's ID,
provider, display name, lifecycle/health states, declared scopes, and
created/updated/last-validated timestamps. They never query or return
credential references, provider configuration, validation results, or setup
state. These reads do not authorize a lifecycle action by themselves. Separate
guarded lifecycle operations are described in
[connection lifecycle capabilities](connection-capability-lifecycle.md).

The asset-governance write operation is:

`PATCH /internal/v1/capabilities/assets/{asset_id}/governance`

It accepts the existing Denali `GovernanceUpdate` JSON: `status` is one of
`approved`, `unreviewed`, `unwanted`; schema-optional `owner` is at most 256
characters and `notes` at most 4000 characters. The public gateway requires
callers to supply all three fields explicitly, preventing accidental clearing
of owner or notes by an omitted field. The receiver requires an 8–128-character
`Idempotency-Key` consisting of letters, digits, `_`, or `-`. A successful first
request returns 200; a retry of the same tenant/key/body returns the recorded
result without another update; a different action using that key returns 409.
The action and actor are durably recorded by migration 021.

Two additional Denali-owned manual response operations are available:

- `POST /internal/v1/capabilities/detections/{detection_id}/responses` (201) uses
  `RuntimeResponseCreate`: `action_type` is one of Denali's five response proposal
  types, `target_asset_id` is required for target-specific types, and `justification`
  is 1–2000 characters. This records a proposal only; it does not call a provider.
- `PATCH /internal/v1/capabilities/detections/{detection_id}/responses/{response_id}`
  (200) uses `RuntimeResponseReview`: `decision` is `approved` or `rejected`, with
  optional `review_note` at most 2000 characters. The original requester cannot
  review their own proposal. Approval records a decision only and does not call
  a provider.

Both require the same distinct `denali:write` M2M purpose, current organization
admin membership, and `Idempotency-Key` as governance. Migration 022 records their
request hashes, actors, and outcomes atomically with the app-owned mutation.

Two confirmed job-start controls are also available for **Denali-local**
connections, not Platform-owned shared-connector validation:

- `POST /internal/v1/capabilities/connections/{connection_id}/validate` with
  `{ "confirm": true }`.
- `POST /internal/v1/capabilities/connections/{connection_id}/collect` with
  `{ "collection_kind": "<allowlisted kind>", "confirm": true }`.

Both require the same live org-admin and `denali:write` checks, a UUID connection
owned by the mapped tenant, an active/fully configured provider, and an
`Idempotency-Key` (the public Platform adapters require UUID-v4). Collection
kinds are explicitly matched to the connection's
provider and selected scopes. A successful call returns a bounded 202 job receipt,
not provider data. Migration 023 stores immutable action receipts and existing
durable job tables track execution. Same-key retries return the same receipt;
if the API stopped before dispatch, replay dispatches that saved queued job.
Duplicate worker delivery is safe under the existing database claim. A failed
referenced job instead returns 409; a deliberate retry uses a new key after cooldown.
Active jobs are deduplicated; a new key cannot restart a recently completed job
within five minutes (429). Missing dispatch/storage fails closed. These actions
only start existing read-only validation/collection work; they never mutate
customer AWS/GitHub resources. Platform shared AWS validation is a separate
cross-database operation and is not covered by these routes.

Every request requires a short-lived Clerk M2M token from the configured gateway
machine, scoped to the Denali receiver machine and bound to `org_id` and `user_id`.
GET requires token purpose `results:read`; ordinary mutations require
`denali:write`; connection disable/delete and shared disable require the distinct
`denali:connections:destructive` purpose. Denali independently checks **current** Clerk membership,
requires `org:admin` for every mutation, looks up the pre-existing Clerk-org →
Denali-tenant mapping, and scopes all repository operations by that tenant UUID.
A removed member is denied even if their gateway token has not expired. Responses
are `Cache-Control: no-store`.

Unknown routes and unconfigured receivers return 404; invalid tokens 401;
non-members and non-admin writers 403; malformed input 422; unmapped organizations
and missing assets 404. Clerk membership lookup failure returns 503, never access.

## Durable evidence import

`POST /internal/v1/capabilities/vulnerabilities/imports` returns 202 with
`{id, state}` for one native durable evidence-import job. Its JSON contains:
`target_asset_id` (UUID), `syft_report` and `grype_report` (native report objects),
`authoritative` (boolean, default true), `expected_org_id` (the caller's active
Clerk Organization), and `confirmed` (literal JSON true). Extra fields and all
query parameters are rejected. The complete streamed request is limited to
2 MiB, including both reports; oversized requests return 413 before parsing or
staging. The organization guard returns 409 if the active organization changed.

Import submission requires `denali:write`, live organization-admin membership,
and the same `Idempotency-Key` format. Denali verifies an active AI workload in
the resolved tenant and validates native Syft/Grype image identity before staging
reports in the existing private transient store. Migration 025 commits the
native job and audit atomically; the audit contains actor, request hash, and
tenant-bound job identity, never raw reports or credential material. Reports use
separate random-job prefixes, so a concurrent losing retry only removes its own
staged copy. An uncertain commit acknowledgement retains evidence for replay.

The same tenant/key/actor/canonical report payload returns the existing job;
a different payload or actor returns 409. A replay after API-container replacement
repairs a queued job whose dispatch was not recorded. Dispatch failure returns
503 and retains the queued job and evidence for that retry. Duplicate dispatch
is safe because the existing durable worker claims one bounded PostgreSQL lease.
Polling uses `vulnerability-import-status`; validation, ingestion, evaluation,
retry, and stale worker recovery retain the existing worker implementation.
Transient objects staged before an API-container exit preceding the database
commit remain subject to the existing evidence-store retention policy.

## Connection lifecycle extension

The named lifecycle action receiver and five additional bounded setup/shared reads
are documented in [connection lifecycle capabilities](connection-capability-lifecycle.md).
They preserve all seven native providers and the shared AWS app-entitlement and
organization-allowlist boundary. Destructive disable/delete require a distinct
downstream purpose and optional OAuth consent, current administrator membership,
exact target confirmation, organization guard and durable idempotency. Setup state,
links and codes retain their existing one-time protocols and are never stored in
the action ledger. Migration 024 adds its identifier-only audit records.

## Deliberate exclusions

The receiver does not expose health, account administration, invitations, provider
callbacks, raw connection configuration, credential leases, customer-cloud mutation,
or arbitrary API forwarding. New capabilities require their own authorization,
audit, idempotency, and durable-work review. This change does not
alter the production shared-AWS pilot, legacy connectors, or the development-only
shared-GitHub connector. This is not full Denali API parity.

| Surface | In this release | Still outside MCP/CLI |
| --- | --- | --- |
| Denali results | 35 named reads, including bounded metadata-only runtime export and safe setup reads | Unreviewed future API paths |
| Denali records/jobs | Governance, response proposal/review, evidence import, validation/collection, connector lifecycle/setup | Provider callbacks, invitations and user administration |
| Customer AWS/GitHub resources | No mutation | All resource-changing actions and remediation |

Expand in that order: first review additional existing Denali-record mutations
one operation at a time for RBAC, tenancy, idempotency, durable jobs, and tests;
then design separately scoped customer-cloud actions with new provider grants,
preview/dry-run, explicit approval, audit, and rollback. Never expose arbitrary
Denali URLs or provider SDK calls through the gateway.

Password-based user creation stays in its secure browser workflow; passwords
must never enter a model or chat. Bulk invitations affect shared Clerk
Organization membership across applications and require a separate design for
each action, recipient role, confirmation, and audit before becoming a human
MCP capability. GitHub CI OIDC ingestion retains its verified workflow/run/repository
trust boundary rather than accepting a human gateway identity. Operator-only
CLI evaluation execution has no browser/API write route; its issue and detection
evaluation histories are already named reads. AWS/Azure connection creation
uses `declared_scopes` to select allowed read planes; it does not accept arbitrary
runtime collection settings. There is no standalone runtime-settings update API.

## Production enablement and release gate

Review and merge this PR to `main`; never deploy its feature branch. The protected
production workflow applies migrations 021–025 before deploying these receivers.
It must pass Ruff, the full Python and PostgreSQL integration suites, Modal
compilation, and the frontend build. The new internal routes remain disabled
until the production Modal core Secret has these names configured:

| Variable | Meaning |
| --- | --- |
| `DENALI_RESULTS_GATEWAY_MACHINE_ID` | Exact Clerk production machine ID of the results gateway caller |
| `DENALI_RESULTS_RECEIVER_MACHINE_ID` | Exact Clerk production Denali receiver machine ID |
| `DENALI_PLATFORM_MACHINE_SECRET_KEY` | Secret key of the production Denali receiver machine, used to verify incoming M2M tokens |
| `CLERK_SECRET_KEY` | Existing production Clerk backend key, used for live membership lookup |

The gateway machine must be allowed to request M2M tokens scoped **only** to the
receiver machine. The Platform gateway owns the user's production OAuth grant
and must mint a fresh, short-lived downstream M2M token with the verified
`org_id`, `user_id`, and exact purpose. Do not copy development machine IDs,
keys, OAuth clients, or Denali data into production. Production values belong
in Modal Secrets, never Vercel or Git.

After configuration, redeploy the exact reviewed `main` SHA through the
protected production workflow. Verify no-token, wrong-machine, wrong-purpose,
removed-member, unmapped-org, member-write, admin-write, replay/conflict, and
two-organization isolation through the deployed gateway. The direct Modal
receiver and Vercel `/api` proxy should continue to pass their existing health
checks. Disable the receiver by removing the two machine-ID variables and
redeploying the current reviewed `main` SHA; do not roll back an applied SQL
migration.
