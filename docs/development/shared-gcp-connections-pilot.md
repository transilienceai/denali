# Shared Google Cloud connections for Denali

This opt-in integration lets Denali reuse a Platform-owned, keyless Google Cloud
connection. It is default off and requires the reviewed companion Platform GCP
release. Existing Denali-managed Google Cloud connections, onboarding, credentials
and collection remain unchanged. Local tests do not establish hosted acceptance.

## Request and identity flow

```text
Denali browser → same-origin /api → Denali Clerk session and org-admin checks
                                      ↓ short-lived Denali machine token
                            Platform app and Clerk org entitlement
                                      ↓ exact project ID and immutable number
                       Platform keyless per-connection Google principal
                                      ↓ fixed allowlisted metadata reads
                    Existing Denali normalizers → Denali Neon evidence
                                      ↓ existing product-owned capabilities
                               Platform API and CLI and MCP
```

Platform owns the reusable connection and Google access. Denali stores only its
Platform UUID, selected project IDs/numbers and approved evidence scopes. Google
tokens, service-account JSON keys and native ADC configuration never cross the
Platform-to-Denali boundary. Every read rechecks the active app, org, connection,
scope and immutable project binding. A shared failure does not try native Google
credentials or create a replacement connection.

The four read-only evidence scopes are `gcp.vertex_ai`, `gcp.agent_builder`,
`gcp.code_to_cloud` and `gcp.ai_activity`. They cover the existing Denali AI
inventory, Cloud Run/Functions/GKE deployment metadata and Vertex AI audit
metadata normalizers. They do not authorize arbitrary Google APIs, remediation,
secret reads, complete audit payloads or Concierge CSPM. Activity collection uses
one fixed window of at most 24 hours across all pages. Reads are bounded to 100
items per page; asset collection is capped at 100 pages per type, and activity
retains Denali's 5,000-record partial-coverage safeguard.

## Operator configuration

Apply Platform's migration 004 before deploying its updated connections API,
even while the GCP feature is off. Review Platform's dedicated reader and
provisioner workload identity trust and narrow permissions separately. Do not
copy or widen Denali's existing Google trust: Modal identity binds workspace,
environment and app, and the provisioning worker has a separate identity.
The operator project is `transilience-platform` (`915339327481`); this is not
implicitly a customer project selection.

After review and Platform hosted verification, set these backend values in the
Denali environment being tested:

- `DENALI_PLATFORM_GCP_ENABLED=true`, only in its existing core Modal Secret.
  Every API and durable worker already mounts that same secret. Do not put this
  flag or machine credentials in the frontend or duplicate them in provider secrets.
- The existing `DENALI_PLATFORM_CONNECTIONS_ORIGIN`,
  `DENALI_PLATFORM_MACHINE_SECRET_KEY` and
  `DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS` must select the matching environment
  and exact pilot org. Continue the existing reviewed deployment-origin setup.
- Platform must register the Denali machine and explicitly entitle that org/app
  for the requested Google evidence scopes. A Clerk org role alone is insufficient.

No new Clerk secret, Google customer JSON key or Denali migration is required.
Keep all `DENALI_GCP_*` native configuration unchanged. Keep the flag false until
Platform provisioning, Google trust, APIs and customer grant approval are ready.

## Admin onboarding and collection

1. Open Denali Connections in the entitled Clerk org. The reusable Google Cloud
   panel appears only when enabled; an upstream failure is shown as an error.
2. Enter a name, 1–8 exact `project-id:project-number` pairs and evidence scopes.
   Registration queues durable Platform principal provisioning. Repeating an
   unchanged submitted form reuses its request ID, rather than creating a second plan.
   Failed or expired provisioning jobs expose Retry provisioning. Platform computes
   retry availability; an active lease keeps that button disabled. Retry uses the
   existing plan and durable queue, not a new connection.
3. When provisioning is ready, download and inspect the fixed project setup script.
   An administrator of those exact projects runs it in Google Cloud Shell. It
   grants Cloud Asset Viewer, Browser and Service Usage Consumer on those projects.
   AI activity additionally needs Private Logs Viewer for Data Access audit events.
   Calls consume the selected projects' API quota and may incur API charges; they
   do not enable APIs or grant resource writes. No JSON key is created or uploaded.
4. Click Validate project access and poll its durable status. Platform checks the
   selected IDs/numbers and scope permissions. Healthy access is not collection.
5. Click Use in Denali. Attachment creates an idempotent, tenant-scoped reference
   without modifying or replacing any native Denali connection.
6. Open that Denali connection, validate and collect Google Cloud evidence. The
   existing durable validation/collection workers, job receipts and normalizers
   call Platform's fixed metadata read API, then persist evidence to Denali Neon.
7. Read the resulting inventory, coverage and activity through existing Denali
   API/CLI/MCP capabilities. This pilot adds no new MCP onboarding tool names;
   named validation, collection, job polling and results already share Denali's
   implementation. Denali record-write permission does not grant Google IAM writes.

Denali's Disable and Delete configuration actions retire only Denali's local use;
delete requires disablement first. The shared panel's separately confirmed
Disable shared connection stops access for all entitled apps. Neither action
removes Google IAM grants or previously collected evidence. Customer IAM cleanup
is a separate administrator step. Native Cloud Shell launch/completion is rejected
for a shared reference, preventing accidental execution under the wrong principal.
After global disablement, Delete disabled shared plan requires typing its exact
current name and retains Platform's creator-app ownership check. This tombstones
the shared plan for all apps; existing Denali references must be retired separately.

## Release acceptance and rollback

Before enabling users, verify hosted registration → provisioning → reviewed
project grants → Platform validation → Denali attachment → durable validation
and collection → inventory/activity and MCP result reads. Test two orgs, member
versus admin, duplicate registration/attachment, revoked scopes, disabled shared
connection, bounded pagination, local disable/delete and unchanged native GCP
validation/collection. Inspect browser responses and logs for credential exposure.
Empty inventory is valid only with explicit completed coverage, not as proof that
resources were discovered. Validation and collection must have separate receipts.

Rollback by setting `DENALI_PLATFORM_GCP_ENABLED=false` and redeploying the
reviewed Denali revision, then disabling the affected Platform connection if
needed. Shared workers fail closed; native connections continue unchanged.
Keep applied migrations and existing evidence. Concierge adoption requires its
own bounded CSPM adapter and permission review and is not included here.

Google's [workload identity guidance](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers)
and [Cloud Asset paging contract](https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/assets/list),
plus [Modal OIDC identity claims](https://modal.com/docs/guide/oidc-integration),
govern the operator trust and fixed paging boundary.
