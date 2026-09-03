# Denali contributor and agent contract

These instructions apply to the entire repository. Read
[`docs/architecture/0028-hosted-multi-tenant-runtime.md`](docs/architecture/0028-hosted-multi-tenant-runtime.md)
before changing authentication, tenancy, API routing, persistence, background work, deployment,
or provider onboarding.

## Architecture that must remain true

- The hosted request path is browser -> Vercel -> same-origin `/api/*` rewrite -> Modal FastAPI
  -> Neon PostgreSQL. Do not make the browser call Modal or Neon directly.
- Clerk authenticates people and supplies the active Organization. A Clerk Organization maps to
  one internally generated Denali tenant UUID. Never substitute a Clerk `org_...` string into
  Denali UUID columns.
- Every tenant-owned database read and mutation must be scoped by the resolved Denali tenant UUID.
  Do not accept a tenant ID from a request body, query string, route parameter, callback browser
  session, or client-controlled header.
- The API is the authorization boundary. `org:member` is read-only and `org:admin` may mutate.
  Frontend role checks are presentation only.
- Organization invitations and direct Clerk user creation go through authenticated, admin-only
  FastAPI routes using the server-resolved active Organization. Never accept an Organization ID
  for these operations from the browser. Bulk invitations must remain bounded and return
  per-address outcomes without logging addresses.
- The root redirect, `/healthz`, API documentation, and documented provider callbacks are the
  intentional public routes. New `/v1/*` routes require verified Clerk authentication and an
  active Organization by default unless a reviewed callback protocol supplies equivalent
  one-time authorization.
- PostgreSQL is the durable source of truth. Hosted API containers never run migrations at
  startup; migrations run explicitly through the Modal migration function under the repository's
  PostgreSQL advisory lock.
- Work that must survive a request or container lifetime needs a PostgreSQL job record and a Modal
  worker spawned with only durable identifiers. Do not add new production `BackgroundTasks`,
  `sleep`, process-local locks, or process-local result dictionaries for durable work.
- Connection validation already follows the durable job pattern. Provider collection endpoints
  currently use API-container background tasks and are a documented migration gap; do not copy
  that implementation into new workflows or describe it as restart-safe.

## Secrets and provider identity

- Vercel may receive only public frontend/server configuration, currently
  `VITE_CLERK_PUBLISHABLE_KEY` and `MODAL_API_ORIGIN`.
- Vercel Production uses the Clerk production instance, the `denali-production` Modal app, and
  production Neon. Vercel Preview uses the Clerk development instance, the isolated `denali-dev`
  Modal app, and an isolated Neon `denali-dev` branch/database. Never route a development Clerk
  token to the production Modal verifier or route a preview build to the production database.
- Backend, database, and provider integration secrets belong in Modal Secrets. Never put
  `CLERK_SECRET_KEY`, a database DSN, provider secret, token, or private key in a `VITE_*`
  variable, Vercel build output, logs, fixtures, screenshots, or the repository.
- A password supplied for admin-created Clerk users is transient request material. Forward it to
  Clerk once; never log it, persist it, include it in an API response, job, error detail, or
  telemetry. If Clerk user creation succeeds but Organization membership fails, delete that
  just-created Clerk user as a consistency rollback.
- Modal Secrets contain Denali-operated integration identity and configuration, not one set of
  customer cloud credentials per tenant.
- Tenant cloud access is keyless or installation/consent based: AWS assume-role with external ID,
  Azure tenant consent and selected subscriptions, GCP per-connection principal grants, and
  GitHub App installation plus exact repository selection.
- Persist only tenant-specific identifiers, selected scopes, hashed one-time state, validation
  evidence, and coverage state in Neon. Do not persist customer access keys, service-account JSON,
  OAuth access tokens, GitHub user tokens, setup codes, private keys, or raw source snapshots.
- Provider callbacks must resolve tenant and connection exclusively from verified, expiring,
  one-time state stored before redirect. They must not depend on the browser's currently active
  Organization.

## Change standards

- Preserve the `/api` frontend contract and same-origin production callbacks. A new backend route
  normally needs a matching frontend client method, auth/role classification, tenant-scoped
  repository operation, and tests.
- Put SQL changes in a new numbered migration. Never rewrite a migration that may have run in
  Neon. Keep runtime queries compatible with pooled connections and migration work on the direct
  DSN.
- Keep provider validation separate from collection. Healthy means the declared read-only access
  planes were callable; it does not prove that collection ran or that inventory exists.
- Keep observed inventory, findings, issues, activity, detections, and coverage semantically
  separate. Do not manufacture identity or a safety conclusion from missing evidence.
- Use structured identifiers (`tenant_id`, `connection_id`, `job_id`) in operational logs, but
  never tokens, authorization headers, DSNs, secrets, callback codes, or provider payloads.
- Preserve local Compose mode for development. Hosted-only changes must not require Clerk or Modal
  for the local test suite unless the test explicitly covers hosted behavior.
- `DENALI_MODAL_APP_NAME`, `DENALI_MODAL_SECRET_NAME`, and
  `DENALI_MODAL_PROVIDER_SECRET_NAME` are deploy-shell settings. Every environment mounts exactly
  one core Secret and one provider Secret so Modal's local and remote dependency graphs remain
  identical. Production uses `custom-secret` plus `denali-github-provider`; hosted preview uses
  `denali-dev` plus an environment-local provider Secret of the same name. Provider Secrets must
  not duplicate or override core Clerk/Neon keys.

## Required verification

Run the checks proportional to the change, and run all of them before claiming a hosted release is
ready:

```bash
pytest
ruff check .
npm --prefix web ci
npm --prefix web run build
```

For persistence or tenancy changes, also run the PostgreSQL integration suite with
`DENALI_TEST_DSN`. Authentication changes require invalid/expired token, authorized-party,
pending-session, missing-organization, admin/member, organization-switching, and cross-tenant
tests. Durable worker changes require duplicate dispatch, retry, timeout, worker failure, stale
lease, and API-container replacement tests.

Do not declare provider onboarding complete from mocks or a healthy connection badge. Record a
hosted create -> setup/callback -> validate -> disable -> delete pass for each enabled provider,
and test collection separately when collection is in scope.
