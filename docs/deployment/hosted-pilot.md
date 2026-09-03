# Hosted multi-tenant pilot

For the executable sequence, current status, and secret placement matrix, use the
[pilot launch checklist](pilot-launch-checklist.md).

The hosted pilot keeps PostgreSQL as Denali's source of truth and separates the runtime into:

- Vercel for the static Vite application and same-origin `/api` proxy;
- Clerk Organizations for identity, membership, and `admin`/`member` roles;
- Modal for the FastAPI application and durable validation workers;
- Neon for managed PostgreSQL.

The canonical architecture and contributor constraints are in
[ADR 0028](../architecture/0028-hosted-multi-tenant-runtime.md). Repository-wide agent guidance is
in [`AGENTS.md`](../../AGENTS.md).

Provider connections retain their current boundary: they onboard and validate access. They do
not schedule or run collectors automatically.

Connection validation is durable because it uses a PostgreSQL job and a separately spawned Modal
worker. The current manually triggered GitHub source and cloud deployment collection endpoints run
inside the Modal API container with FastAPI background tasks; they are not restart-safe. Do not
extend that pattern. Migrate collection to PostgreSQL-backed Modal jobs before treating collection
as a reliable hosted production workflow.

## 1. Create the Neon database

Create a PostgreSQL 16 Neon project in the same general region as the Modal deployment. Retain
both connection strings:

- `DENALI_DSN`: the pooled (`-pooler`) TLS connection for API and worker traffic;
- `DENALI_MIGRATION_DSN`: the direct TLS connection for schema migrations.

Create a least-privilege runtime role rather than using `neondb_owner`. The migration role must
own the Denali schema; the runtime role needs DML access and sequence usage. Before deploying
the API, run the migration function:

```bash
modal run modal_app.py::migrate_database
```

Migrations use a transaction-scoped PostgreSQL advisory lock and execute each numbered SQL file
once. API containers never migrate on startup.

## 2. Configure Clerk

Create a production Clerk application and:

1. Enable Organizations with membership required and personal accounts disabled.
2. Retain the default `org:admin` and `org:member` roles.
3. Restrict sign-up to invitations for the pilot.
4. Add the final web origin to the allowed origins/authorized parties.
5. Create pilot organizations and invite their users.

The frontend receives only `VITE_CLERK_PUBLISHABLE_KEY`. Put `CLERK_SECRET_KEY`, the PEM
`CLERK_JWT_KEY`, and `CLERK_AUTHORIZED_PARTIES` in the Modal secret. Optionally set
`DENALI_CLERK_ORGANIZATIONS` to a comma-separated organization allowlist. When omitted, every
organization in the invitation-only Clerk instance is eligible.

Denali maps the active Clerk `org_...` identifier to an internal UUID on first access. Every API
query continues to use the UUID tenant predicate. Members can read; only admins can mutate.

## 3. Configure and deploy Modal

Create a core Modal Secret containing the Clerk, Neon, and web variables relevant to the
deployment from `.env.example`. The source default name is `denali-production`; set
`DENALI_MODAL_SECRET_NAME` in the deploy shell when the environment uses another name. At minimum
the core Secret needs:

- `DENALI_DSN`, `DENALI_MIGRATION_DSN`, and `DENALI_WEB_URL`;
- `CLERK_SECRET_KEY`, `CLERK_JWT_KEY`, and `CLERK_AUTHORIZED_PARTIES`;

Provider credentials remain in one separate, environment-local Modal Secret. Set
`DENALI_MODAL_PROVIDER_SECRET_NAME` in the deploy shell to mount it alongside the core Secret.
The provider Secret is applied after the core Secret, so it must not duplicate core keys.
Production uses:

```bash
export DENALI_MODAL_SECRET_NAME=custom-secret
export DENALI_MODAL_PROVIDER_SECRET_NAME=denali-github-provider
```

`DENALI_MODAL_REGION` is evaluated by the local Modal CLI while it builds the deployment, so
export it in the deploy shell (or CI environment); it is not read from the runtime secret.
Set the Secret-name variables in the same deploy environment as the Modal CLI invocation; they are
not runtime values loaded from a Secret.

Deploy production through the checked-in script, which validates combined configuration, runs
migrations and database status, and deploys the app:

```bash
scripts/deploy_modal_prod.sh
```

`api` keeps one warm pilot container. `validation_worker` receives only a validation job UUID,
claims the job in PostgreSQL, and records completion or a bounded failure. A second validation
request for the same tenant and connection returns `already_running`. An expired worker lease is
failed before a later manual retry creates a replacement job.

For AWS, prefer Modal OIDC. Configure AWS to trust `https://oidc.modal.com`, create a
least-privilege role limited to the Denali Modal workspace/application, and set
`DENALI_MODAL_AWS_ROLE_ARN`. The runtime exposes Modal's short-lived identity token through
boto's standard web-identity provider chain.

Do not put the GitHub private key in the image. Store its PEM value as
`DENALI_GITHUB_PRIVATE_KEY` in the Modal secret. The local file-based variable remains available
for Compose development.

The provider entries in this Secret configure Denali-operated identities and artifact publishers.
Do not add a tenant's access keys, service-account JSON, OAuth access token, or GitHub personal
token. Each organization grants access through the provider-specific assume-role, consent,
principal, or App-installation flow; tenant identifiers and selected scopes are stored in Neon.

## 4. Configure Vercel and the domain

Create a Vercel project with `web` as its Root Directory. Set:

- `VITE_CLERK_PUBLISHABLE_KEY` to the Clerk production publishable key;
- `MODAL_API_ORIGIN` to the deployed Modal `api` origin without a trailing slash.

The programmatic `vercel.mjs` configuration builds `dist`, routes `/api/:path*` to Modal without
caching, and falls back to `index.html` for browser navigation. Add the production domain and
redeploy after changing environment variables.

Use these production provider URLs:

- web URL: `https://denali.example.com`;
- GitHub setup URL: `https://denali.example.com/api/v1/connections/github/setup/callback`;
- GitHub OAuth callback: `https://denali.example.com/api/v1/connections/github/oauth/callback`;
- Azure consent redirect: `https://denali.example.com`.

Set `DENALI_GITHUB_CALLBACK_URL`, `DENALI_AZURE_CONSENT_REDIRECT_URI`, `DENALI_WEB_URL`,
`CLERK_AUTHORIZED_PARTIES`, and `DENALI_CORS_ORIGINS` to the final values. The browser normally
uses the same-origin proxy; CORS remains restricted for diagnostics and controlled direct calls.

### Isolated Vercel preview environment

Do not point a Vercel preview using Clerk development keys at `denali-production`. Create an
isolated hosted development stack named `denali-dev`:

1. Create a Neon branch and empty database named `denali-dev`, owned by a dedicated
   `denali_dev_owner` role. Collect pooled and direct DSNs that explicitly select the
   `denali-dev` database and that role; do not reuse the production owner DSN.
2. Create a Modal environment named `denali-dev`, then create a Secret named `denali-dev` inside
   it with those DSNs, the Clerk development `sk_test_...` key and matching development JWKS PEM,
   and the exact stable Vercel preview origin in `CLERK_AUTHORIZED_PARTIES`, `DENALI_WEB_URL`, and
   `DENALI_CORS_ORIGINS`.
3. Deploy and migrate the separate Modal application with the checked-in helper:

   ```bash
   scripts/deploy_modal_dev.sh
   ```

4. Set Vercel Preview `VITE_CLERK_PUBLISHABLE_KEY` to the matching Clerk development
   publishable key and Preview `MODAL_API_ORIGIN` to the resulting `denali-dev` Modal API origin.
   Redeploy the preview.

Clerk users and Organizations are instance-specific. Create development-only test Organizations
and memberships; do not expect production identities or Organization IDs to exist in development.
Keep all Production-scoped Vercel variables and the `denali-production` Modal Secret unchanged.

## 5. Acceptance and operations

For two separate Clerk organizations, verify:

1. organization switching changes `/api/v1/context` and all displayed data;
2. a member can read but receives `403` for every mutation;
3. an admin can update governance and operate connections;
4. AWS, Azure, GCP, and GitHub complete their hosted setup, callback, validation, disable, and
   delete flows;
5. killing an API container does not stop an already spawned validation worker;
6. Neon restore procedures have been exercised on a non-production branch.

Monitor Vercel external-origin errors, Modal function failures/timeouts, Neon connection and
storage metrics, and validation jobs that remain `running` beyond their lease. Logs may contain
tenant UUID, connection UUID, and job UUID, but never Clerk tokens, provider tokens, setup codes,
private keys, or database credentials.
