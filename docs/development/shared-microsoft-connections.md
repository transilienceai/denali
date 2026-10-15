# Shared Azure and Microsoft Entra development backport

## Entra-first development rollout

This focused `dev` refresh tracks reviewed production Microsoft source
`4974a196da56645a9132e3cf05173979d0f2847a`; the provider adapter is byte-identical.
It does not merge the divergent production branch or import its newer gateway,
resource-remediation, shared Workspace or other connector implementations.
Existing native Workspace/Shasta and native/shared AWS/GitHub behavior stay intact.

Enable only `DENALI_PLATFORM_ENTRA_ENABLED=true` after the separately reviewed
Platform dev broker, dedicated **Transilience Platform Entra Dev** registration,
exact `tran-test` → approved Microsoft tenant admission and tenant-wide Graph
application admin consent are ready. Keep `DENALI_PLATFORM_AZURE_ENABLED=false`
or absent. Entra needs no Azure subscription or Azure Reader assignment. Creating
or approving an Azure registration, subscription grant or pilot is deferred.

Keep the development backend identity, Clerk membership and Neon database
isolated. Do not copy the production Entra credential or production org admission.
The dedicated registration's callback must be exactly:

```text
https://transilience-transilience-platform-dev--transilience-pla-73050c.modal.run/internal/v1/connections/entra/setup/callback
```

The callback must match the reviewed deployed broker before consent. The Graph
application bundle remains only `Directory.Read.All` and `AuditLog.Read.All`,
with no delegated user permission, Microsoft write, mail or file permission.
Provider credentials live only in Platform dev's environment-local
`transilience-platform-entra` Secret, never Denali or Vercel.

Acceptance is create → tenant-specific admin consent/callback → validate all
declared Graph planes → attach in Denali dev → durable Entra collection →
existing inventory/activity/findings reads through CLI/MCP. Verify anonymous,
member/admin, other-org and revoked/disabled boundaries; test destructive
lifecycle only on an explicitly approved disposable reference. Validation proves
callability, not collection. Licensing or empty sign-in coverage stays explicit.

This source change authorizes no merge, deployment, flag, secret, database,
consent or admission mutation. Both Microsoft flags remain off until separately
approved environment-specific activation.

## Shared Microsoft boundary

This implementation is dark by default and is not production acceptance evidence.
`DENALI_PLATFORM_AZURE_ENABLED` and `DENALI_PLATFORM_ENTRA_ENABLED` each default to
false. Activation also requires the existing HTTPS
`DENALI_PLATFORM_CONNECTIONS_ORIGIN`, backend-only
`DENALI_PLATFORM_MACHINE_SECRET_KEY`, and exact
`DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS` allowlist. Provider application credentials
remain exclusively in Platform's dedicated Microsoft connector configuration;
native Denali Microsoft identities and existing connections are unchanged.
The initial pilot additionally requires owner-reviewed Platform admission for
the exact Microsoft tenant and Azure subscription UUIDs in this Organization's
app entitlement. The admission lists default to empty. Organization admins
cannot self-admit a foreign provider target through consent feedback or a
browser body; they ask their Platform administrator to approve the target first.

The browser calls relative `/api/v1/shared/connections/{azure|entra}`. Denali
resolves the Clerk Organization and internal Denali tenant, then calls the fixed
Platform machine API. Members may read projected configuration, list, validation
status and Azure's reviewable script. Create, setup, validation, attachment,
disable and delete require an Organization admin. GET setup also requires admin
because Platform rotates one-time state. Browser bodies cannot select a Clerk
Organization, Denali tenant or credential reference. The supplied Microsoft
tenant UUID is an exact provider binding, never Denali authorization.

Create accepts a stable request UUID, display name, Microsoft tenant UUID and
declared scopes. Azure also accepts 1–8 selected unique subscription UUIDs and
optional names. Azure shared scopes are `azure.ai_services`, `azure.ai_platform`,
`azure.ai_activity` and `azure.code_to_cloud`. Foundry agent runtime activity stays
in the native flow. Shared Entra uses all four scopes together:
`entra.ai_applications`, `entra.permissions`, `entra.sign_ins` and
`entra.directory_audits`. Its registered Directory.Read.All / AuditLog.Read.All
application bundle is disclosed as one consent decision.

Plan creation does not establish readiness. Setup returns a Microsoft consent
URL using Platform's fixed callback
`/internal/v1/connections/{azure|entra}/setup/callback`. Platform owns hashed,
expiring, one-time state and verifies the exact returned Microsoft tenant;
Denali has no shared callback and does not use the browser's current Organization
to complete consent. The customer returns to Denali manually and refreshes.
Azure administrators separately inspect and execute the downloaded Reader script
in their own Cloud Shell. It targets the exact application service principal and
selected subscriptions. Denali never executes role assignments or grants consent.

Attachment requires current Platform `availability=ready`, `health_state=healthy`
and all requested validated/entitled scopes. Denali records only the same shared
connection UUID, `platform_shared_azure` or `platform_shared_entra` reference,
provider tenant, selected subscriptions, scopes and coverage plan in its existing
tenant-scoped `provider_connection`. A conflicting native connection is rejected;
there is no migration or fallback. Native setup launch/completion routes reject
shared references. Disable/delete of the shared plan is distinct from disable/delete
of Denali's reference and never revokes Microsoft consent or Azure IAM automatically.

Existing durable validation and collection jobs, leases and Modal workers execute
the attached connection. Microsoft routers select shared readers by credential
type; native credentials are consulted only for native connections. Broker failure,
feature disablement, entitlement loss or a mismatched response fails closed.
Validation demonstrates callable metadata planes. Collection feeds existing Denali
inventory/activity sinks, correlation and finding evaluation separately.

The canonical fixed reads are:

| Provider | Named operations and bindings |
| --- | --- |
| Azure | `subscription_metadata` with an explicitly declared Azure scope; `resources` with an allowlisted resource type; `activity` with a 24-hour maximum window. Every read binds the selected subscription and provider tenant. |
| Entra | `service_principals`, `oauth_grants`, `app_role_assignments` with one service-principal UUID, `sign_ins` with 1–10 app UUIDs and a 24-hour maximum window, and `directory_audits` with a 24-hour maximum ApplicationManagement window. Every read binds the provider tenant. |

Reads contain at most 100 projected dictionary items, `operation`, `tenant_id`,
Azure `subscription_id` and an opaque `next_page_token`. Azure cursors are bounded
at 2048 characters and Entra at 8192; repeat cursors, invalid bindings, oversized
pages and record limits fail closed. Denali never sends provider URLs, Graph paths,
arbitrary filters, ARM queries or tokens. Shared Entra activity collection covers
24 hours per run, explicitly shown in the UI and result `lookback_hours`; native
Entra's existing 168-hour default is preserved.

This focused backport preserves dev's current named MCP/CLI result reads for
inventory, activity and findings. The connection setup, validation and collection
job controls use the existing authenticated browser APIs. Main's expanded
capability/lifecycle/job receiver framework is not part of this backport. No new
tool name, login scope, typed command or client package release is introduced.
Microsoft plan/consent/script handoffs are admin-only browser operations, excluded
from model tools. The fixed route and read classifications are recorded in
`shared-microsoft-contract.v1.json` beside this document.

Before any activation, run the local Python/frontend/PostgreSQL gates and obtain
separate authorized hosted acceptance: create → tenant-specific consent/callback →
customer-approved Azure Reader setup (Azure only) → validate → attach → durable
collection → disable → delete for each enabled provider and two Organization
boundaries. Entra-only acceptance does not activate or accept Azure. Verify
licensing/retention limitations and cross-tenant rejection. Local fakes are not a
provider acceptance pass. This change makes no OAuth request, provider permission
change, cloud call, merge or deployment.

## Isolated dev preparation

This backport starts from `origin/dev` at
`7e853c0c139921b807b838c0622d5c8aedab6cd1` and ports only reviewed Microsoft
implementation `4974a196da56645a9132e3cf05173979d0f2847a` (original adapter also
reviewed at `2d2de5904af8a60f81f1fd0263855220494e433d`). It does not merge main
into dev, change the dev read capability catalog, replace worker leases, add
migrations, or alter existing shared AWS/GitHub admission and native identities.
The Microsoft gate uses `DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS`; the older dev
bridge transport retains its existing AWS/GitHub behavior and Platform checks.

Follow [hosted-dev-environment.md](hosted-dev-environment.md) for the isolated
Clerk development instance, `denali-dev` Modal app/core Secret, environment-local
provider Secret and Neon development branch. The browser entrypoint stays
`https://denali-dev.transilience.cloud`; its only API origin is same-origin `/api`.
The new browser paths are `/api/v1/shared/connections/azure` and
`/api/v1/shared/connections/entra`, with their existing-shaped `config`, `setup`,
`validation`, `validate`, `use-in-denali`, `disable`, and delete suffixes; Azure
also has `setup.sh`. Microsoft callbacks go directly to the corresponding
`/internal/v1/connections/{azure|entra}/setup/callback` on the separately isolated
Platform development origin, never production or a browser-selected org.

Keep both Microsoft flags false until the dev Platform connector, dedicated dev
operator applications, exact callback URLs and owner-reviewed tenant/subscription
admission are ready. Add only exact Clerk development organization IDs to the
Microsoft allowlist; a production org, user, membership or Denali UUID is not a
development mapping. The machine sender and receiver pair must belong to the
shared Clerk development instance. No new OAuth scope or shared session-template
claim is required. Do not add CLERK_AUDIENCE, change public client IDs, copy a
production key into dev, or change existing provider identities.

For one consolidated operator call, prepare all dev and production app identifiers,
fixed callbacks, admitted tenant/subscription UUIDs, flags and machine/org bindings
in advance. The customer separately approves Microsoft consent and executes the
reviewable Azure Reader script for the exact environment/application targets. This
repository change makes no secret/configuration write, OAuth request or provider
grant. Keep dev and production consent/setup outcomes separate in the call record.
After separately approved rollout from reviewed dev, run the runbook smoke checks
and the two-organization create/setup/validate/collect/disable/delete acceptance.
