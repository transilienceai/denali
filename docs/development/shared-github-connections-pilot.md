# Shared GitHub connections in Denali

Denali can reuse a Platform-owned GitHub installation for the same Clerk
Organization. Platform owns installation consent and short-lived repository
tokens; Denali owns validation, bounded source analysis, inventory and findings.
Existing Denali-owned GitHub installations continue using their original App.

## Request and identity flow

```text
Browser Clerk session → Denali /api/v1/shared/connections/github/*
  → Denali resolves its tenant and active Clerk org, enforcing admin mutations
  → short-lived Clerk M2M → Platform app/org/read-scope entitlement
  → separate Platform GitHub App → Denali's pinned subset of repository IDs

Denali validation/collection job → PostgreSQL lease → Modal worker
  → Platform fresh single-repository token → existing bounded GitHub analysis
  → Denali Neon results → existing API, CLI and MCP capabilities
```

No App private key is copied into Denali. Tokens remain server memory only and
never reach browser responses, persisted configuration or job results. Shared
failures do not fall back to Denali's native identity. An unavailable shared
broker therefore cannot silently create or widen a native connection.

## Enable one reviewed organization

Deploy the reviewed Denali `main` revision through its protected production
workflow. This feature is disabled by default. First review Platform's separate
production App identity, credentials and exact pilot-org entitlement. Then:

- Set `DENALI_PLATFORM_GITHUB_ENABLED=true` in Denali's existing core Modal
  Secret; do not add a frontend variable or change native `DENALI_GITHUB_*`.
- Retain the existing matching `DENALI_PLATFORM_CONNECTIONS_ORIGIN`,
  `DENALI_PLATFORM_MACHINE_SECRET_KEY` and exact
  `DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS` allowlist.
- Grant only that registered Denali app and Clerk org the intended
  `github.repository_metadata`, `github.repository_contents` and
  `github.actions_workflows` scopes in Platform. Preserve its AWS/GCP scopes
  and all other organizations. Platform's deployment flag and separate
  `transilience-platform-github` Secret must also be configured.
- Redeploy through the normal protected workflow after a core Secret edit.

Only after the reviewed bridge is deployed and enabled, start the installation
from Denali as described below. This creates the required Platform one-time state;
do not manually install early and attempt to import that installation afterward.
Selected-repository consent and hosted acceptance happen after this enablement.

No Denali schema migration is added. The shared reference, exact repository
metadata, validation jobs and collection jobs use the existing tenant tables.
Neither enabling the feature nor adding entitlement imports an old installation.

## Install and attach

1. Sign in to Denali as the intended Organization admin and open Connections.
2. Choose **Connect GitHub** in the reusable GitHub section. Install the
   separate Platform App on only the repositories selected for this pilot.
3. Complete GitHub user authorization. Platform verifies the installer can
   access the installation, checks the App identity and consumes one-time
   state. Its success page asks you to return to Denali.
4. Return to the original Denali tab, refresh and explicitly select repository
   IDs for this Denali connection. Choose **Use selected repositories in Denali**.
   Selection starts empty and resets on refresh; newly available repositories
   are never automatically selected. The backend rechecks account, installation,
   scopes and live token issuance before storing a shared reference.
5. Validate the attached connection, then collect source. Health proves access;
   collection and resulting evidence are separate acceptance checks.

The App's Setup URL ends in `/v1/connections/github/setup/callback`; its
OAuth callback ends in `/v1/connections/github/oauth/callback`. Both belong
to the stable Platform production API origin, not Denali's old callbacks.
GitHub's installation redirect ID is untrusted until installer OAuth verifies
it. See [GitHub's setup warning](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url).

Repeated explicit attachment is idempotent for the same organization, Platform
connection, repository IDs and scopes, regardless of selection ordering. Each
explicit boundary has a deterministic local Denali UUID, separate from the
immutable Platform connection UUID. Selecting another subset or scope boundary
creates another local row; it never rewrites an existing row. The server derives
that UUID from trusted organization identity, not a caller-supplied local ID.

Legacy attachments made without `repository_ids` retain their original local ID
(equal to the Platform ID) and exact saved configuration. If the installation
later gains repositories, validation and collection still use only the saved
repositories and scopes. Every saved numeric ID, node ID, full name and owner
identity must remain unchanged. Refreshed registry identity drift denies access
before requesting a lease. Platform's registry metadata can be stale, so an
exact-ID lease is not by itself proof that GitHub still has the saved name:
Denali checks the live root repository metadata with exact, case-sensitive
identity equality before allowing any content or workflow reads. A rename,
transfer or replacement detected there prevents source-derived evidence and
records failed coverage only; the already-issued lease remains narrowed to its
one saved repository ID. Denali never follows provider redirects to another name.
Each new lease requires fresh root-metadata verification, even if a provider
reuses the same token. A legacy repeat request with different current metadata returns `409`
rather than expanding that saved row. There is no in-place rebinding endpoint.
An explicit subset can coexist with a legacy binding, even if their selections
overlap; use the local ID returned by each attachment for lifecycle operations.

**Installation growth is a separate provider consent change.** Adding a repository
to GitHub's App installation expands that App's accessible resources even though
its read-only permissions stay the same. Obtain the installation owner's consent,
deploy this reviewed pinned-subset compatibility change first, and then complete
Platform's verified setup/authorization flow for the addition. This change does
not edit an installation, authorize a new repository, add a second App, widen
entitlements or change native GitHub connections. Other consuming products must
independently preserve their pinned boundaries before provider consent is expanded.

Installation tokens remain narrowed to one recorded repository
and permitted reads, consistent with [GitHub's token contract](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).

## API CLI and MCP testing

Browser setup routes are same-origin and Clerk authenticated:

| Method and path | Purpose |
| --- | --- |
| `GET /api/v1/shared/connections/github` | Safe installation metadata |
| `GET /api/v1/shared/connections/github/{id}/repositories` | Available installation repository metadata |
| `POST /api/v1/shared/connections/github/setup` | Admin installation launch |
| `POST /api/v1/shared/connections/github/{id}/use-in-denali` | Admin attachment of an explicit pinned subset |
| `POST /api/v1/shared/connections/github/{id}/disable` | Creator-owned, organization-wide shared disable |

Here `{id}` is the Platform connection UUID. An attachment body can contain:

```json
{
  "repository_ids": [123456789],
  "declared_scopes": ["github.repository_metadata", "github.repository_contents"]
}
```

IDs must be positive JSON integers, present in the currently verified installation,
non-duplicated and bounded to 1–500. Scopes must be an entitled subset and include
metadata. Omission of `repository_ids` preserves the legacy attachment contract;
it does not upgrade existing rows. The response `id` is the **local Denali UUID**;
`credential_reference.platform_connection_id` remains the **Platform UUID**.
No local ID, organization ID, App identity or credential can be supplied in this body.

Attached references use existing durable validation/source collection endpoints
and existing MCP connection-validate, connection-collect, job-polling and result
tools. Setup consent remains a browser workflow; no new lifecycle MCP tool is
advertised. Ask MCP to list connections, validate this exact shared connection,
collect its GitHub source using the returned local UUID after confirming the target org, follow the durable
job, and show repository-derived inventory and coverage. These operations do not
write GitHub source or dispatch workflows.

Check anonymous denial, member read/admin mutation boundaries, a non-pilot org's
404, replayed callbacks and an out-of-bound repository denial. Validate/collect
the same native test connection before and after deployment to confirm it keeps
using Denali's original App. Do not claim full hosted acceptance from mock tests
or a green connection alone.

The local regression gate proves that separately consented installation additions
do not widen old token requests, saved configuration or collector coverage; identity
drift in refreshed registry metadata denies access before a lease, while stale
registry/live-provider drift (including case-only changes) denies content,
workflow reads and source-derived evidence; subset attachment is deterministic and tenant-scoped; and its
durable jobs and local Disable/Delete do not affect another binding. Hosted
acceptance still requires separately approved repository consent, old and new
connection validation/collection, and inspection of each exact repository boundary.

## Disable and rollback

**Disable for organization** stops new Platform leases for every consuming app;
only the creating app may perform it. Already issued tokens can survive until
their expiry. Local Denali Disable/Delete affects only its reference and does
not uninstall or disable the shared installation; retained evidence remains.
Customer administrators uninstall the separate App in GitHub when needed.
There is no shared-installation delete API in this slice.

To roll back new access, set `DENALI_PLATFORM_GITHUB_ENABLED=false` and redeploy
the reviewed current `main` revision normally. Keep native configuration intact.
Shared references fail closed while disabled; they never acquire native tokens.
