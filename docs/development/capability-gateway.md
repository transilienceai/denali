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
Detail operations require `?id=<UUID>`; `runtime-session-detail` instead requires a
64-character lowercase hex session key. Lists accept only their documented Denali
filters, `limit` (1–100), and `offset` (0–100000). Invalid/duplicate/unknown query
parameters return 422. The receiver forwards to the existing tenant-scoped Denali
handler; it never accepts a URL, tenant ID, or arbitrary route from the gateway.

| Area | Read operations |
| --- | --- |
| Inventory | `inventory-summary`, `assets`, `asset-detail`, `sources-coverage` |
| Findings | `findings-summary`, `findings`, `finding-detail` |
| Vulnerabilities | `vulnerabilities-summary`, `vulnerabilities`, `vulnerability-detail`, `vulnerability-import-status` |
| Issues | `issues-summary`, `issues`, `issue-detail`, `issue-evaluations` |
| Code-to-cloud | `code-to-cloud-deployments`, `code-to-cloud-observations` |
| Activity | `activity-summary`, `activity`, `activity-detail`, `runtime-sessions`, `runtime-session-detail` |
| Detections | `detections-summary`, `detections`, `detection-detail`, `detection-evaluations` |

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
or arbitrary API forwarding. Existing Denali write APIs for vulnerability imports
and validation/collection are **not yet** gateway capabilities; each needs its own
authorization, audit, idempotency, and durable-work review. This change does not
alter the production shared-AWS pilot, legacy connectors, or the development-only
shared-GitHub connector. This is not full Denali API parity.

## Production enablement and release gate

Review and merge this PR to `main`; never deploy its feature branch. The protected
production workflow applies migrations 021 and 022 before deploying the receiver.
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
