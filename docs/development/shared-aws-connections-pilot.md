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

The Connections page includes a small shared-AWS pilot panel when the dev
backend has these routes configured. For the first end-to-end check, select one
commercial AWS Region and the `aws.bedrock_agents` scope, deploy the template,
validate, then click **Test scoped AWS read**. Denali asks the platform for a
15-minute scoped lease and performs a bounded `ListAgents(maxResults=1)` call
server-side. The response contains only the Region, pass state, and a zero-or-one
sample count; it never returns temporary keys or agent identifiers to the
browser. The platform rejects a lease for a Region outside selected coverage.
This proves the identity and read path, not evidence collection or a safety
conclusion. Existing Denali collectors remain unchanged.

No additional Clerk key is required for this path beyond the existing Denali
dev sender machine secret and platform dev receiver machine secret. Keep both
in their respective Modal Secrets; Vercel and the browser receive neither.
The stable `denali-dev.transilience.cloud` domain may require Vercel SSO for
browser testing, while the backend's direct health endpoint remains separate.

No production deployment, public `api.transilience.cloud` reverse proxy, MCP
endpoint, automatic synchronization, or switch of Denali collectors is included
in this PR. The customer-side dev test role, live validation, and successful
scoped read are prerequisites before claiming the pilot works end-to-end.
