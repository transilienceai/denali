# Denali pilot launch checklist

Use this as the ordered launch-control artifact. Do not skip ahead: the production URL is an
input to Clerk and provider callbacks, and the Modal URL is an input to Vercel.

## Current checkpoint — 2026-09-17

The [agent security roadmap](../product/agent-security-roadmap.md) is the current priority and P0
exit contract. This checklist remains the operator control for completing its hosted evidence.

- [x] Production Vercel and Modal deployments are healthy at the canonical domain and same-origin
  API boundary.
- [x] Production uses the Clerk production instance, `denali-production` Modal app, and production
  Neon database.
- [x] Apply migrations 001 through `020_azure_foundry_agent_runtime_activity.sql` through the
  protected deployment workflow.
- [x] Durable validation, primary provider collection, AWS AgentCore runtime collection, and Azure
  Foundry runtime collection use PostgreSQL jobs and Modal workers.
- [x] Azure Repos hosted lifecycle and code-to-cloud acceptance passed on 10 September 2026.
- [x] Azure Foundry AIDR production acceptance passed on 14 September 2026 with one Anna session,
  six metadata-only activities, complete coverage, and zero prohibited content fields.
- [x] Deploy the fail-closed configuration gate that requires core plus AWS, Azure, GCP, Entra,
  Google Workspace, GitHub, and Azure Repos configuration before a production release.
- [ ] Complete and retain create, setup/callback, validate, collect, disable, and delete evidence
  for every enabled provider that does not yet have a full dated record.
- [ ] Complete two-organization isolation testing with non-empty evidence.
- [x] Create a real second Clerk Organization, retain a complete AgentCore collection with two
  inventory resources, and pass hosted UI read isolation in both directions. Direct API mutation
  and `org:member` checks remain under the broader isolation gate. See the
  [2026-09-15 record](../product/two-organization-isolation-2026-09-15.md).
- [x] Reconcile the currently signed-in Clerk user with both evidence Organizations, repeat
  non-empty switching, exercise the hosted `org:member` read-only UI, restore `org:admin`, and
  retain the authorized-party limitation on backend-minted direct-API probe tokens.
- [ ] Split the Neon runtime and migration roles, enable production alerts/backups, and complete a
  restore drill.
- [x] Create and verify distinct least-privilege Neon runtime and migration roles and rotate the
  Modal DSNs. A later protected deployment replaced the warm production application and the
  deployed status function succeeded through the rotated runtime DSN. The obsolete owner CRUD
  compatibility grant was removed on 17 September and the deployed function then returned all 21
  connection rows through the runtime role. See the
  [2026-09-15 role record](../product/neon-role-split-2026-09-15.md).
- [x] Exercise Modal function timeout classification and alert delivery in an isolated hosted
  drill, then stop the disposable app. See the
  [2026-09-15 record](../product/modal-alert-hosted-acceptance-2026-09-15.md).
- [ ] Enable and exercise Vercel deployment/runtime monitoring.

Control-plane access blockers verified on 17 September 2026:

- the available Neon account has no projects and must be invited to the production project (or be
  given a scoped API credential) before alerts, recovery settings, and a restore branch can be
  exercised;
- Vercel GitHub login returns `github_account_not_linked`; the existing Vercel account must first
  be opened with its current email/passkey method and then linked to GitHub; and
- the member read-only UI was exercised and the admin role restored; the remaining direct-API
  matrix needs a browser-issued Clerk token because production backend-minted tokens omit `azp`.

See the [split operator/administrator handoff](../handoffs/2026-09-17-p0-operator-admin-actions.md)
for the exact remaining sequence.

Production runtime:

```text
Web:   https://denali.transilience.cloud
API:   https://transilience-denali-prod--denali-production-api.modal.run
Neon:  production database; migrations 001 through 020 applied
```

The Azure Foundry acceptance record is
[`2026-09-14-azure-foundry-aidr-production-acceptance.md`](../handoffs/2026-09-14-azure-foundry-aidr-production-acceptance.md).

## Historical checkpoint — 2026-09-01

- [x] Hosted multi-tenant application code is implemented and committed.
- [x] The configured Clerk development publishable key resolves to a live Clerk JWKS endpoint.
- [x] Select `https://denali.transilience.cloud` as the permanent production URL.
- [x] Store the Clerk backend key material in Modal. The pilot still uses a Clerk development
  instance and requires hosted organization acceptance before launch approval.
- [x] Provision Neon database `denali`; pooled/direct connection strings are stored in Modal.
- [x] Apply all 12 migrations through `012_tenant_connection_constraints.sql`.
- [x] Create Modal environment `denali-prod` and its current `custom-secret`.
- [x] Add the production origin settings and deploy the Modal API/worker in `us-east`.
- [x] Configure and deploy Vercel project `transilience-a55654db/denali` under
  `transilience-dev`; the duplicate Pro project has been removed.
- [x] Verify the canonical frontend and same-origin API boundary: `/` returns `200`,
  `/api/healthz` returns `200`, and unauthenticated `/api/v1/context` returns `401`.
- [ ] Complete two-organization Clerk acceptance.
- [ ] Configure and accept AWS, Azure, Microsoft Entra, GCP, and GitHub individually.

Production runtime at that checkpoint:

```text
Web:   https://denali.transilience.cloud
API:   https://transilience-denali-prod--denali-production-api.modal.run
Neon:  database denali; migrations 001 through 012 applied
```

## Prioritized remaining work at that checkpoint

### P0 — make the empty product useful

1. Configure the existing GitHub App in Modal and complete create, setup callback, validation,
   source collection, disable, and delete from the hosted UI.
2. Configure AWS Modal OIDC and the onboarding bucket/principal, then complete the same hosted
   lifecycle. GitHub plus AWS unlocks the first complete source-to-cloud acceptance path.
3. Move Clerk from development keys to a production instance before inviting pilot users.
4. Test `org:member` read-only enforcement and two-organization isolation with non-empty data.

### P1 — complete provider coverage

1. Configure and accept Google Cloud.
2. Configure and accept Azure.
3. Use a least-privilege Neon runtime role instead of an owner-capable runtime DSN.

### P2 — hardening and operations

1. Replace API-container collection background tasks and in-memory status with PostgreSQL-backed,
   idempotent Modal collection jobs before treating hosted collection as restart-safe.
2. Enable Modal failure/timeout alerts, Vercel deployment monitoring, and Neon alerts/backups.
3. Run and document a Neon restore drill.
4. Add the Clerk publishable key to Vercel Development if Vercel-hosted development builds are
   required; Production and Preview are already configured.

Live authenticated smoke acceptance recorded on 2026-09-01:

- Clerk sign-in and active organization authorization return `200` from `/v1/context`.
- AirtelAfrica loads with the admin connection controls.
- Switching to `muzaffartest1` and back reauthorizes successfully without browser errors.
- All eleven protected product pages load, and a deep-link refresh succeeds.
- The active tenant currently has zero connections, so zero inventory is expected.
- Core Modal configuration is ready; AWS, Azure, GCP, and GitHub provider configuration is absent.

## Ordered TODOs

### 1. Choose the production URL and regions

- [x] Choose the final web URL: `https://denali.transilience.cloud`.
- [x] Use Neon in AWS `us-east-2` and Modal in `us-east`.
- [x] Reserve the custom domain and create the Vercel project so its stable
  `<project>.vercel.app` URL is known.

Record these non-secret values:

```text
DENALI_WEB_URL=https://denali.transilience.cloud
DENALI_CORS_ORIGINS=https://denali.transilience.cloud
CLERK_AUTHORIZED_PARTIES=https://denali.transilience.cloud
DENALI_MODAL_REGION=us-east
```

### 2. Finish Clerk

- [ ] Use a Clerk production instance for the real pilot (`pk_live_...` / `sk_live_...`). The
  currently configured key is a development `pk_test_...` key.
- [ ] Enable Organizations and require organization membership.
- [ ] Keep `org:admin` and `org:member`; disable personal-account access.
- [ ] Restrict signup to invitations.
- [ ] Create the approved pilot organizations and invite users.
- [ ] Add the final production origin and redirect URLs in Clerk.
- [ ] Copy the Secret Key and the PEM JWT public key from Clerk Dashboard → API Keys.

Destinations:

| Variable | Destination | Classification | Required |
| --- | --- | --- | --- |
| `VITE_CLERK_PUBLISHABLE_KEY` | Vercel | Public client configuration | Yes |
| `CLERK_SECRET_KEY` | Modal secret | Secret | Yes |
| `CLERK_JWT_KEY` | Modal secret | Public cryptographic key, backend-only | Yes |
| `CLERK_AUTHORIZED_PARTIES` | Modal secret/config | Non-secret origin allowlist | Yes |
| `DENALI_CLERK_ORGANIZATIONS` | Modal secret/config | Non-secret Clerk organization ID allowlist | Recommended for the pilot |

Never add `CLERK_SECRET_KEY` to Vercel or any `VITE_...` variable.

### 3. Provision Neon

- [x] Create a PostgreSQL project in the selected region.
- [ ] Create a least-privilege runtime role and a migration/owner role.
- [x] Obtain the pooled PgBouncer runtime URL and direct migration URL with TLS required.
- [x] Store both only in Modal, never in Vercel.
- [ ] Enable backups and record a restore-test procedure.

| Variable | Value | Destination | Classification |
| --- | --- | --- | --- |
| `DENALI_DSN` | Neon pooled runtime URL | Modal secret | Secret |
| `DENALI_MIGRATION_DSN` | Neon direct migration URL | Modal secret | High-privilege secret |

### 4. Create the core Modal secret

Create an ignored local file named `.env.modal.production`. It must contain only the core
backend values at this stage:

```dotenv
DENALI_DSN=
DENALI_MIGRATION_DSN=
DENALI_WEB_URL=https://<production-domain>
DENALI_CORS_ORIGINS=https://<production-domain>
CLERK_SECRET_KEY=
CLERK_JWT_KEY=
CLERK_AUTHORIZED_PARTIES=https://<production-domain>
DENALI_CLERK_ORGANIZATIONS=
```

Then create or replace the named Modal secret without placing values in shell history:

```bash
modal secret create --from-dotenv .env.modal.production denali-production
```

- [x] Confirm `modal secret list --env denali-prod` includes the deployed `custom-secret`.
- [ ] Keep `.env.modal.production` local and ignored; do not commit or send it in chat.

### 5. Migrate and deploy Modal

`DENALI_MODAL_REGION` and the Secret-name settings are deploy-shell variables, not values loaded
from runtime Secrets. Production keeps core values in `custom-secret` and GitHub values in
`denali-github-provider`.

After the deployment workflow change is reviewed and merged, open GitHub Actions → **Deploy
Modal production**, run it from `main`, and enter the exact full merged commit SHA. The protected
workflow runs the migration and deployment steps and verifies both health endpoints and the
unauthenticated authorization boundary. See the
[change and release process](../development/change-and-release-process.md); do not deploy
production from a feature branch or Vercel preview.

- [x] Record the deployed Modal `api` HTTPS origin.
- [x] Verify `<modal-origin>/healthz` returns `{"status":"ready","version":"0.1.0"}`.
- [ ] Enable Modal failure and timeout alerts.

### 6. Create and deploy Vercel

Create a Vercel project from this repository with `web` as the Root Directory. Vercel needs
only these two values:

| Variable | Value | Classification |
| --- | --- | --- |
| `VITE_CLERK_PUBLISHABLE_KEY` | Clerk publishable key | Public client configuration |
| `MODAL_API_ORIGIN` | Deployed Modal origin, without trailing slash | Public server configuration |

For the first URL-reservation deployment, when Modal is not deployed yet, set
`MODAL_API_ORIGIN=https://example.com`. This is a temporary non-secret placeholder: the UI will
build and publish, while `/api/*` remains intentionally unusable. Record Vercel's production URL,
use it to configure Clerk and Modal, deploy Modal, then replace the placeholder with the real
Modal origin and redeploy Vercel.

- [x] Add the production values to Vercel Production.
- [x] Add the Clerk development publishable key and the isolated `denali-dev` Modal origin to
  Vercel Preview. Never point a development Clerk preview at `denali-production`.
- [x] `MODAL_API_ORIGIN` is configured for Vercel Development. Add the Clerk publishable key to
  Development only if that target will be used.
- [x] Deploy the project and attach `denali.transilience.cloud`.
- [ ] Verify an authenticated refresh and SPA navigation. Unauthenticated `/` and
  `/api/healthz` are verified.
- [x] Confirm Vercel contains only the public Clerk publishable key and Modal origin.

Development preview deployment recorded on 2026-09-02:

- Modal environment, app, and Secret: `denali-dev`;
- Modal API origin: `https://transilience-denali-dev--denali-dev-api.modal.run`;
- Neon branch and database: `denali-dev`, owned by `denali_dev_owner`;
- Vercel branch alias:
  `https://denali-git-codex-custom-clerk-profile-transilience-a55654db.vercel.app`;
- database migrations: 13, latest `013_connection_collection_jobs.sql`;
- authenticated Account, Organization, Members, active-Organization context, and same-origin API
  routing verified from the hosted preview.
- Profile member administration is implemented through admin-only Modal API routes: single and
  bulk Clerk invitations plus direct Clerk user creation. Direct creation requires password
  sign-in to be enabled in the matching Clerk development/production instance; Denali does not
  store or return the initial password.

Shared development environment updated and authenticated on 2026-09-15:

- stable domain: `https://denali-dev.transilience.cloud`;
- Vercel custom environment: `denali-dev`, tracking `dev`;
- stable review alias: `https://denali-dev-preview-transilience-a55654db.vercel.app`;
- Clerk development claims aligned with production and application-specific `aud` removed;
- Modal authorized parties, canonical web URL, and CORS origins synchronized for the stable
  domain, stable review alias, and local ports 3000 and 3001;
- `denali-dev` migrated and deployed from `a98bf9c8e805c911460e71e962b1836d80f3f474`;
- authenticated context and the application data API set returned `200` through the same-origin
  proxy.

Use the [hosted development environment runbook](../development/hosted-dev-environment.md) for
future changes. A push to `dev` now deploys Modal development automatically. A Modal Secret edit
must be followed by a manual **Deploy Modal development** workflow dispatch so warm containers load
the new values.

### 7. Reconcile the final URL

If the deployed URL differs from step 1, update all of these together and redeploy:

- [x] `DENALI_WEB_URL`
- [x] `DENALI_CORS_ORIGINS`
- [x] `CLERK_AUTHORIZED_PARTIES`
- [ ] Clerk allowed origins and redirect URLs
- [ ] `DENALI_ENTRA_CALLBACK_URL`
- [ ] `DENALI_GITHUB_CALLBACK_URL`

### 8. Accept Clerk tenancy before adding providers

- [x] Sign in through the hosted UI.
- [ ] Verify users without an active organization cannot load Denali.
- [ ] Verify `org:member` can read and receives `403` for mutations.
- [ ] Verify `org:admin` can mutate governance and connections.
- [ ] Switch between two organizations and confirm `/api/v1/context` returns different Denali
  tenant UUIDs and no data crosses organizations. Switching and reauthorization are verified;
  repeat with non-empty fixtures to prove data isolation.

### 9. Add providers one at a time

Add each provider's variables to an ignored provider-only dotenv and create or replace a separate
provider-operator Modal Secret. Set `DENALI_MODAL_PROVIDER_SECRET_NAME` alongside
`DENALI_MODAL_SECRET_NAME` when deploying `modal_app.py`. Keeping provider variables separate
avoids replacing an existing core Secret whose values are intentionally unreadable. Complete each
provider's hosted acceptance before starting the next provider.

#### AWS

```text
DENALI_MODAL_AWS_ROLE_ARN
DENALI_AWS_ONBOARDING_BUCKET
DENALI_AWS_PRINCIPAL_ARN
```

- `DENALI_MODAL_AWS_ROLE_ARN` and the bucket/principal identifiers are non-secret configuration.
- Configure AWS to trust Modal OIDC and scope the role to the exact Modal workspace, environment,
  app, and functions. Do not add long-lived AWS access keys.

#### Azure

```text
DENALI_AZURE_ONBOARDING_BUCKET
DENALI_AZURE_CLIENT_ID
DENALI_AZURE_CLIENT_SECRET
DENALI_AZURE_REPOS_CALLBACK_URL=https://<production-domain>/api/v1/connections/azure-repos/oauth/callback
```

- `DENALI_AZURE_CLIENT_SECRET` is the secret; the other entries are identifiers/configuration.
- The Cloud Shell script creates or confirms the customer tenant's local service principal and
  grants Reader only on the subscriptions the customer selects. Azure onboarding has no browser
  consent callback because the operator application requests no API permissions.
- When Azure Repos is enabled, register the callback above, add Azure DevOps delegated `vso.code`
  to the operator application, and have an Azure DevOps administrator add its tenant-local service
  principal as a Basic user with read access only to the selected projects or repositories.
- When Azure Foundry runtime activity is selected, the customer enables tracing and connects the
  Foundry project to Application Insights. The existing selected-subscription Reader grant covers
  component discovery and the read-only query action. Denali projects only allowlisted metadata
  and does not request prompt, response, system-instruction, or tool payload fields.

#### Google Cloud

```text
DENALI_GCP_ONBOARDING_BUCKET
DENALI_GCP_OPERATOR_PROJECT_ID
DENALI_GCP_WORKLOAD_IDENTITY_PROVIDER
DENALI_GCP_RUNTIME_SERVICE_ACCOUNT
```

- These are non-secret identifiers. The provider value is the canonical
  `projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>` name.
- Configure the pool to trust Modal's OIDC issuer and restrict assertions to the production
  workspace, environment, and app. Grant that external principal Workload Identity User on the
  runtime service account.
- At container startup Denali writes Modal's short-lived identity token and an external-account
  ADC configuration to private container-local files. Do not create or commit a service-account
  JSON key.

#### Microsoft Entra application evidence

```text
DENALI_ENTRA_CLIENT_ID
DENALI_ENTRA_CLIENT_SECRET
DENALI_ENTRA_CALLBACK_URL=https://<production-domain>/api/v1/connections/entra/setup/callback
```

- `DENALI_ENTRA_CLIENT_SECRET` is the operator secret. The client ID and callback are identifiers.
- Register the exact same-origin callback on the multi-tenant Entra application.
- Confirm the application exposes only `Directory.Read.All` and `AuditLog.Read.All` application
  permissions and that the UI discloses both before redirecting the customer.

#### GitHub

```text
DENALI_GITHUB_APP_ID
DENALI_GITHUB_CLIENT_ID
DENALI_GITHUB_CLIENT_SECRET
DENALI_GITHUB_APP_SLUG
DENALI_GITHUB_PRIVATE_KEY
DENALI_GITHUB_CALLBACK_URL=https://<production-domain>/api/v1/connections/github/oauth/callback
```

- `DENALI_GITHUB_CLIENT_SECRET` and `DENALI_GITHUB_PRIVATE_KEY` are secrets.
- Store the PEM private key directly in Modal; do not add it to Vercel or the repository.
- Configure GitHub's setup callback as
  `https://<production-domain>/api/v1/connections/github/setup/callback`.

### 10. Launch gate

- [ ] Run one complete onboarding, validation, disable, and delete flow for each enabled provider.
- [ ] Confirm validation survives API-container replacement and duplicate requests return
  `already_running`.
- [ ] Enable Vercel deployment monitoring, Modal alerts, and Neon database alerts/backups.
- [ ] Review logs for tenant/job/connection IDs and verify tokens and secrets never appear.
- [ ] Record the deployed URLs, resource owners, rollback procedure, and acceptance date.
- [x] Record Azure Foundry AIDR collection, metadata-only privacy, coverage, and Runtime-page
  presentation against the Anna reference agent on 14 September 2026.

## Secret summary

Actual secrets that must be stored in Modal are:

```text
CLERK_SECRET_KEY
DENALI_DSN
DENALI_MIGRATION_DSN
DENALI_AZURE_CLIENT_SECRET                 # when Azure is enabled
DENALI_ENTRA_CLIENT_SECRET                 # when Entra evidence is enabled
DENALI_GITHUB_CLIENT_SECRET                # when GitHub is enabled
DENALI_GITHUB_PRIVATE_KEY                  # when GitHub is enabled
```

`CLERK_JWT_KEY` is public key material but remains backend-only. Vercel receives no private
secret: only `VITE_CLERK_PUBLISHABLE_KEY` and `MODAL_API_ORIGIN`.
