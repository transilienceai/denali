# Denali pilot launch checklist

Use this as the ordered launch-control artifact. Do not skip ahead: the production URL is an
input to Clerk and provider callbacks, and the Modal URL is an input to Vercel.

## Current checkpoint — 2026-09-01

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
- [ ] Configure and accept AWS, Azure, GCP, and GitHub individually.

Production runtime:

```text
Web:   https://denali.transilience.cloud
API:   https://transilience-denali-prod--denali-production-api.modal.run
Neon:  database denali; migrations 001 through 012 applied
```

## Prioritized remaining work

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

Live authenticated smoke acceptance completed on 2026-09-01:

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

`DENALI_MODAL_REGION` is a deploy-shell variable, not a value loaded from the runtime secret.
If the secret is not named `denali-production`, also export its name as
`DENALI_MODAL_SECRET_NAME`.

```bash
export DENALI_MODAL_REGION=<modal-region>
export DENALI_MODAL_SECRET_NAME=denali-production
modal run modal_app.py::migrate_database
modal run modal_app.py::database_status
modal deploy modal_app.py
```

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
- database migrations: 12, latest `012_tenant_connection_constraints.sql`;
- authenticated Account, Organization, Members, active-Organization context, and same-origin API
  routing verified from the hosted preview.
- Profile member administration is implemented through admin-only Modal API routes: single and
  bulk Clerk invitations plus direct Clerk user creation. Direct creation requires password
  sign-in to be enabled in the matching Clerk development/production instance; Denali does not
  store or return the initial password.

### 7. Reconcile the final URL

If the deployed URL differs from step 1, update all of these together and redeploy:

- [x] `DENALI_WEB_URL`
- [x] `DENALI_CORS_ORIGINS`
- [x] `CLERK_AUTHORIZED_PARTIES`
- [ ] Clerk allowed origins and redirect URLs
- [ ] `DENALI_AZURE_CONSENT_REDIRECT_URI`
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

Add each provider's variables to `.env.modal.production`, replace the Modal secret with
`--force`, redeploy Modal, and complete its hosted acceptance before starting the next provider.

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
DENALI_AZURE_CONSENT_REDIRECT_URI=https://<production-domain>
```

- `DENALI_AZURE_CLIENT_SECRET` is the secret; the other entries are identifiers/configuration.
- Register the final redirect URL before browser acceptance.

#### Google Cloud

```text
DENALI_GCP_ONBOARDING_BUCKET
DENALI_GCP_OPERATOR_PROJECT_ID
```

- These are non-secret identifiers.
- Configure keyless runtime credentials for Google Application Default Credentials. Do not commit
  a service-account JSON key. GCP acceptance is blocked until Modal can obtain that identity.

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

## Secret summary

Actual secrets that must be stored in Modal are:

```text
CLERK_SECRET_KEY
DENALI_DSN
DENALI_MIGRATION_DSN
DENALI_AZURE_CLIENT_SECRET                 # when Azure is enabled
DENALI_GITHUB_CLIENT_SECRET                # when GitHub is enabled
DENALI_GITHUB_PRIVATE_KEY                  # when GitHub is enabled
```

`CLERK_JWT_KEY` is public key material but remains backend-only. Vercel receives no private
secret: only `VITE_CLERK_PUBLISHABLE_KEY` and `MODAL_API_ORIGIN`.
