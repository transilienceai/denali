# Denali capability receiver (dev integration, not deployed)

Denali remains the owner of its data and authorization. The Transilience gateway is
an authenticated client of these **internal** routes, not a database reader. This
integration branch starts from `dev` and preserves its existing results bridge and
shared AWS/GitHub connection routes. It does not merge into or deploy production
`main`.

## Request contract

`GET /internal/v1/capabilities/{operation}` accepts exactly one named operation.
Detail operations require `?id=<UUID>`; `runtime-session-detail` instead requires a
64-character lowercase hex session key. Lists accept only their documented Denali
filters, `limit` (1–100), and `offset` (0–100000). Invalid/duplicate/unknown query
parameters return 422. The receiver forwards to the existing tenant-scoped Denali
handler; it never accepts a URL, tenant ID, or arbitrary route from the gateway.
Code-to-cloud deployments and observations default to a 100-item gateway page;
both accept `limit` and `offset` for subsequent pages. Their existing browser
routes retain the unbounded default when those parameters are omitted.

| Area | Read operations |
| --- | --- |
| Connections | `connections`, `connection-detail` (Denali-local status, not Platform connector configuration) |
| Inventory | `inventory-summary`, `assets`, `asset-detail`, `sources-coverage` |
| Findings | `findings-summary`, `findings`, `finding-detail` |
| Vulnerabilities | `vulnerabilities-summary`, `vulnerabilities`, `vulnerability-detail`, `vulnerability-import-status` |
| Issues | `issues-summary`, `issues`, `issue-detail`, `issue-evaluations` |
| Code-to-cloud | `code-to-cloud-deployments`, `code-to-cloud-observations` |
| Connections | `connections`, `connection-detail` |
| Activity | `activity-summary`, `activity`, `activity-detail`, `runtime-sessions`, `runtime-session-detail` |
| Detections | `detections-summary`, `detections`, `detection-detail`, `detection-evaluations` |

This is **28 named reads across eight Denali areas**, not the whole Denali
API. For scale, the current production OpenAPI has 68 public paths before
this receiver. The browser retains all of those app-specific routes; MCP/CLI
receives only this reviewed catalog.

`connections` accepts `limit` (1–100, default 20) and `offset` (0–100000)
and returns a stable ID-ordered page with `has_more`. `connection-detail`
requires `?id=<UUID>`. Both read only the Denali-local connection's ID,
provider, display name, lifecycle/health states, declared scopes, and
created/updated/last-validated timestamps. They never query or return
credential references, provider configuration, validation results, or setup
state. These read operations alone do not grant connection job starts;
those require the separate write checks below.

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
active jobs are deduplicated; a new key cannot restart a recently completed job
within five minutes (429). Missing dispatch/storage fails closed. These actions
only start existing read-only validation/collection work; they never mutate
customer AWS/GitHub resources. Platform shared AWS validation is a separate
cross-database operation and is not covered by these routes.

Every request requires a short-lived Clerk M2M token from the configured gateway
machine, scoped to the Denali receiver machine and bound to `org_id` and `user_id`.
GET requires token purpose `results:read`; mutations (POST/PATCH) require
`denali:write`. Denali independently checks **current** Clerk membership,
requires `org:admin` for every mutation, looks up the pre-existing Clerk-org →
Denali-tenant mapping, and scopes all repository operations by that tenant UUID.
A removed member is denied even if their gateway token has not expired. Responses
are `Cache-Control: no-store`.

Unknown routes and unconfigured receivers return 404; invalid tokens 401;
non-members and non-admin writers 403; malformed input 422; unmapped organizations
and missing assets 404. Clerk membership lookup failure returns 503, never access.

## Deliberate exclusions

The receiver does not expose health, account administration, invitations, provider
callbacks, CloudFormation/setup artifacts, raw connection configuration, credential
leases, runtime-session export, connection disable/delete, customer-cloud mutation,
or arbitrary API forwarding. Existing write APIs for vulnerability imports,
connection lifecycle, provider setup/callbacks, and Platform shared-AWS
validation are **not yet** gateway capabilities. The typed job starts above
apply only to Denali-local connections. The shared AWS/GitHub connector APIs
remain on `dev`; this branch does not change their contracts. This is not full
Denali API parity or customer-cloud resource write access.

| Surface | In this release | Still outside MCP/CLI |
| --- | --- | --- |
| Denali results | 28 bounded reads | Raw exports and unreviewed future API paths |
| Denali records/jobs | 3 audited record writes and typed Denali-local validation/collection job starts | Connection lifecycle, provider setup/callbacks, import, Platform shared-AWS validation, invitations and admin |
| Customer AWS/GitHub resources | No mutation | All resource-changing actions and remediation |

## Release gate

Run Ruff, the complete Python suite, the PostgreSQL integration suite with
`DENALI_TEST_DSN`, Modal module compilation, frontend build, and a development
Clerk-org-switch/removed-member/admin/member acceptance pass before merge/deploy.
Migration 023 must run before enabling the job routes. Do not configure
production gateway IDs or deploy from this feature branch.
