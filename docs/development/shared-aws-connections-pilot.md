# Shared AWS connections: Denali development pilot

This is an **opt-in shared-service pilot**, not a replacement for Denali's AWS
role or scanning path. The shared registry identifies an AWS account by Clerk org,
partition, and account ID. It marks Denali's own validated connection as
`legacy_validated`; other apps see `requires_shared_setup` until a separate
platform-owned trust path is validated. No app may use a legacy Denali role as
shared AWS access.

## Dev-only setup

After the platform service has a dedicated **development** Neon database and
Modal app, provision a Clerk development machine for Denali and grant its M2M
tokens access only to the platform receiver machine. In the platform registry,
enable `registered_app(app_id='denali', clerk_machine_id=<Denali machine ID>)`
and an explicit `app_entitlement` for each pilot Clerk org. Configure only the
Denali **development** Modal environment with:

- `DENALI_PLATFORM_CONNECTIONS_ORIGIN` in the separate
  `denali-platform-connections-dev` Secret: HTTPS origin of the dev platform API.
  The reviewed `dev` deployment mounts it on the API and opt-in sync function,
  without overwriting the existing multi-key core Secret.
- `DENALI_PLATFORM_MACHINE_SECRET_KEY` in the existing `denali-dev` core Secret:
  Denali's dedicated Clerk development machine secret. Do not reuse the human
  Clerk secret or store this in Git/Vercel.

The isolated platform API, Denali machine authentication, pilot-org isolation,
and CloudFormation template were verified on 2026-09-24. The new shared AWS
binding remains unvalidated until its customer-side read-only role is created
and the live STS check succeeds. The Denali feature branch has not been
deployed to the shared `denali-dev` app.

Run `sync_shared_aws_connections` with an exact Clerk `org_...` ID in the
`denali-dev` Modal environment after the PR is reviewed and deployed through the
normal `dev` workflow. The function reads that org's complete AWS connection
set from Denali Neon and sends at most 100 sanitized entries to the platform.
An empty set intentionally tombstones earlier entries for that org; an unknown
org or truncated set fails before sending. Repeat after create, validation,
disable, or delete during the pilot. This manual sync is **not** a durable or
real-time production integration.

Verify from the platform API that Denali sees only its own org's imported
metadata, another entitled app cannot use it as shared AWS access, and a
subsequent empty snapshot removes deleted connections. Do not expose role ARNs,
external IDs, machine secrets, or customer credentials in API responses/logs.

Denali also has separate same-origin `/v1/shared/connections/*` routes. They
derive the org from its verified Clerk session; write routes require an org
admin. They let a dev admin create a **new platform-owned** AWS connection,
download its read-only CloudFormation template, queue/check validation, and disable
it. The template trusts a dedicated platform principal, not Denali's legacy
principal. Existing Denali stacks require a one-time trust update; simply
importing their metadata does not make them usable by other apps.

No production deployment, public `api.transilience.cloud` reverse proxy, MCP
endpoint, automatic synchronization, or switch of Denali collectors is included
in this PR. The shared platform IAM role and a live customer-role validation
are prerequisites for enabling the new path in dev.
