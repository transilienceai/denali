# Shared AWS connections: Denali development pilot

This is an **opt-in metadata sync**, not a replacement for Denali's AWS role or
scanning path. The shared registry identifies an AWS account by Clerk org,
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
Denali **development** Modal core Secret with:

- `DENALI_PLATFORM_CONNECTIONS_ORIGIN`: HTTPS origin of the dev platform API.
- `DENALI_PLATFORM_MACHINE_SECRET_KEY`: Denali's dedicated Clerk development
  machine secret. Do not reuse the human Clerk secret or store this in Git/Vercel.

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

No production deployment, API reverse-proxy route, MCP endpoint, new customer
role, or automatic synchronization is included in this PR.
