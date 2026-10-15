# Shared Azure and Microsoft Entra pilot

## Entra-first production rollout

Microsoft Entra can be enabled independently: set only
`DENALI_PLATFORM_ENTRA_ENABLED=true` after the reviewed Platform Entra broker,
exact organization-to-Microsoft-tenant admission and tenant-wide application
permission admin consent have passed their separate acceptance. Leave
`DENALI_PLATFORM_AZURE_ENABLED=false` or absent. Entra does not require an Azure
subscription or an Azure Reader role; those belong to the later Azure rollout.
The default-off Azure implementation may ship in the same source revision, but
that does not authorize its activation or any Azure subscription IAM changes.

Both native Microsoft connections and already-shipped shared AWS, GitHub, GCP,
Jira and Google Workspace behavior remain independent. Existing Workspace
routes, fixed binding checks and 100-record broker pages with complete
pagination must be retained when refreshing the Microsoft feature onto current
`main`. Run the complete coexistence, contract, PostgreSQL and frontend gates;
do not deploy the older Microsoft feature revision over a newer production app.

Entra pilot acceptance is create → tenant-specific admin consent/callback →
validate the declared Graph planes → attach → durable Entra collection →
existing inventory/activity/findings through API, CLI and MCP. Test revocation,
cross-tenant denial, disable and delete only on an approved disposable reference.
No new OAuth login scope, named model tool or CLI release is needed. A healthy
badge alone is not collection acceptance; empty or unlicensed sign-in coverage
must remain explicit rather than being described as complete evidence.

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

Requests use a page-size hint of at most 100. Reads contain at most that many
projected dictionary items, `operation`, `tenant_id`,
Azure `subscription_id` and an opaque `next_page_token`. Azure cursors are bounded
at 2048 characters and Entra at 8192; repeat cursors, invalid bindings, oversized
pages and record limits fail closed. Denali never sends provider URLs, Graph paths,
arbitrary filters, ARM queries or tokens. Shared Entra activity collection covers
24 hours per run, explicitly shown in the UI and result `lookback_hours`; native
Entra's existing 168-hour default is preserved.

### Entra directory-audit response compatibility

For **only** Entra `directory_audits` with a requested `page_size=100`, the paired
Platform broker and Denali reader accept up to 200 projected dictionary items in
one response. A production Graph response contained 103 valid audit records for
the 100-item hint; rejecting the entire page left directory-audit coverage failed
while the other five planes completed. This is a bounded compatibility exception,
not a larger request, a new permission, or a general Graph page-size guarantee.

Neither side slices an oversized page: every accepted record and the complete
opaque cursor continue through the existing pagination path. Responses of 201 or
more items fail closed. Smaller audit requests retain their exact requested bound;
all other Entra and Azure operations remain strict. Tenant/operation binding,
dictionary-item validation, the 8192-character Entra cursor bound, repeated-cursor
denial, 200-page/20,000-record limits and the maximum 24-hour shared activity
window are unchanged. Metadata that does not match Denali's AI catalog must not
create AI assets or activity merely because coverage completes.

Ship the reviewed broker and this reader fix together; the broker's accepted
response envelope must not exceed the deployed Denali reader's envelope. Then
retry durable collection only for the approved shared Entra connection and verify
all six terminal coverage planes, real normalized inventory/activity, and existing
API/CLI/MCP read parity. A queued retry, healthy validation, or mocked six-plane
test is not live collection acceptance. No database migration, secret, feature
flag, OAuth scope, public tool schema or CLI package release is needed. Azure
activation and other connector behavior remain outside this change.

The named MCP/CLI connection summaries, validation/collection job starts and job
polling, inventory, activity and finding tools reuse this evidence. Setup summaries
add only the non-secret Platform connection UUID. No new tool name, login scope,
typed command or client package release is needed. Microsoft plan/consent/script
handoffs stay excluded from model tools as recorded in the canonical surface map.
The paired Platform PR owns provider brokering and refreshes the reviewed Denali
source pin after this product change is committed.

Before any activation, run the local Python/frontend/PostgreSQL gates and obtain
separate authorized hosted acceptance: create → tenant-specific consent/callback →
customer-approved Azure Reader setup (Azure only) → validate → attach → durable
collection → disable → delete for each enabled provider and two Organization
boundaries. Entra-only acceptance does not activate or accept Azure. Verify
licensing/retention limitations and cross-tenant rejection. Local fakes are not a
provider acceptance pass. This change makes no OAuth request, provider permission
change, cloud call, merge or deployment.
