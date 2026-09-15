# Hosted multi-tenant pilot

For the executable sequence, current status, and secret placement matrix, use the
[pilot launch checklist](pilot-launch-checklist.md).

The hosted pilot keeps PostgreSQL as Denali's source of truth and separates the runtime into:

- Vercel for the static Vite application and same-origin `/api` proxy;
- Clerk Organizations for identity, membership, and `admin`/`member` roles;
- Modal for the FastAPI application, durable validation and collection workers, and bounded
  runtime schedulers;
- Neon for managed PostgreSQL.

The canonical architecture and contributor constraints are in
[ADR 0028](../architecture/0028-hosted-multi-tenant-runtime.md). Repository-wide agent guidance is
in [`AGENTS.md`](../../AGENTS.md). All changes and releases follow the
[protected change and release process](../development/change-and-release-process.md); no code is
pushed directly to `main`, and production deployment is a separate post-merge action.

Provider validation remains separate from collection. Healthy validation queues the first durable
provider collection, and administrators can request a later refresh. Opted-in AWS AgentCore and
Azure Foundry runtime planes also have five-minute schedulers that create the same durable
collection jobs; schedulers never collect inside their own container.

Connection validation and provider collection are durable: the API writes a
PostgreSQL job and separately spawns the applicable Modal worker. Status polling reads PostgreSQL,
so work and terminal results survive API-container replacement.

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
Google Workspace collection additionally requires the non-secret operator identifiers
`DENALI_GOOGLE_WORKSPACE_SERVICE_ACCOUNT` and `DENALI_GOOGLE_WORKSPACE_CLIENT_ID` in that provider
Secret. The Modal runtime service account needs `roles/iam.serviceAccountTokenCreator` on the
Workspace collector service account. Never add a Google service-account JSON key.
Production uses:

```bash
export DENALI_MODAL_SECRET_NAME=custom-secret
export DENALI_MODAL_PROVIDER_SECRET_NAME=denali-github-provider
```

`DENALI_MODAL_REGION` is evaluated by the local Modal CLI while it builds the deployment, so
export it in the deploy shell (or CI environment); it is not read from the runtime secret.
Set the Secret-name variables in the same deploy environment as the Modal CLI invocation; they are
not runtime values loaded from a Secret.

Deploy production through the protected **Deploy Modal production** GitHub Actions workflow after
the reviewed PR is merged. Supply the exact full `main` commit SHA. The workflow re-runs the
release gate and calls the checked-in script, which validates combined configuration, runs
migrations and database status, deploys the app, and verifies production health.

The script refuses feature branches, dirty worktrees, stale `main`, and invocations without an
explicit production flag. It is shown here only for the documented emergency path:

```bash
scripts/deploy_modal_prod.sh --confirm-production
```

GitHub's `production` environment stores only `MODAL_TOKEN_ID` and `MODAL_TOKEN_SECRET` for the
deployment workflow. Denali application secrets remain in Modal Secrets.

`api` keeps one warm pilot container. `validation_worker` receives only a validation job UUID,
claims the job in PostgreSQL, and records completion or a bounded failure. A second validation
request for the same tenant and connection returns `already_running`. An expired worker lease is
failed before a later manual retry creates a replacement job. Healthy validation automatically
dispatches the first provider collection; manual collection remains available for explicit retry
or refresh. Successful cloud collection refreshes dependent GitHub correlation and tenant rule
evaluation as specified by [ADR 0030](../architecture/0030-hosted-evidence-orchestration.md).

AWS AgentCore and Azure Foundry runtime activity use separate five-minute scheduler functions.
Each scheduler selects only due, healthy, opted-in connections and creates a normal durable
collection job. The worker resumes from the last safe cursor with a bounded overlap. Azure's first
run reads 30 minutes and later catch-up is capped at 24 hours. See
[ADR 0035](../architecture/0035-aws-agentcore-runtime-detection-and-response.md) and
[ADR 0036](../architecture/0036-azure-foundry-runtime-detection-and-response.md).

After a reviewed release changes validation or collection orchestration, an operator may enqueue a
bounded refresh of all active connections from the exact deployed `main` revision:

```bash
PYTHONPATH=src python -m denali.api.maintenance refresh --limit 100 --confirm-production
PYTHONPATH=src python -m denali.api.maintenance status --limit 100 --confirm-production
```

The refresh function creates the same durable validation jobs as the authenticated API and relies
on the normal healthy-validation hook for collection. It neither accepts a tenant identifier nor
edits connection evidence directly. The status function prints only structured tenant/connection
identifiers, provider, health, and job states; it never prints names, credentials, or provider
payloads. Run it only from clean, current `main` after the production workflow succeeds.
The checked-in command resolves the functions from the deployed `denali-production` app; do not
replace it with `modal run`, which creates a temporary function graph whose spawned workers do not
have the deployed app's lifecycle.

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

Hosted Syft and Grype imports use `DENALI_EVIDENCE_BUCKET` when configured and otherwise use the
existing `DENALI_AWS_ONBOARDING_BUCKET`. The bucket is operator-owned and private; grant the Modal
OIDC role only `s3:PutObject`, `s3:GetObject`, and `s3:DeleteObject` on the
`denali/evidence-imports/*` prefix. Require encryption and configure a short lifecycle expiry for
defense in depth. Raw reports are transient objects and are deleted after the durable import
reaches a terminal state; only normalized bounded evidence remains in PostgreSQL. See
[ADR 0031](../architecture/0031-hosted-vulnerability-evidence-import.md).

The normal hosted path is automatic submission from a selected repository's default-branch
deployment workflow. Give that job `id-token: write`, set the non-secret GitHub Actions repository
variable `DENALI_CONNECTION_ID` to the existing GitHub connection UUID, and submit the exact
deployed `sha256` image digest. The workflow receives checksum-bound, short-lived upload URLs; it
does not need a Denali token or secret. See
[ADR 0032](../architecture/0032-github-oidc-vulnerability-evidence.md).

After the deployment job has produced native reports for the immutable image, submit them with the
repository action pinned to a reviewed Denali commit:

```yaml
permissions:
  contents: read
  id-token: write

steps:
  # Build, push, deploy, and generate syft.json plus grype.json first.
  - uses: transilienceai/denali/.github/actions/submit-vulnerability-evidence@<pinned-denali-sha>
    with:
      connection-id: ${{ vars.DENALI_CONNECTION_ID }}
      image-digest: ${{ steps.deploy.outputs.image-digest }}
```

The digest must identify the deployed manifest, not merely an image tag or source revision. The
action automatically requests a fresh cloud collection and retries when the deployment is not yet
visible to Denali.

### Azure Foundry runtime activity

Azure Foundry runtime activity is an optional scope on the existing Azure connection. The customer
enables Foundry tracing and connects the project to Application Insights. Denali uses the selected
subscription's existing Reader grant to discover Application Insights components and query only
allowlisted metadata. Denali does not enable tracing, change retention, or request prompts,
responses, system instructions, tool arguments, tool results, request bodies, or response bodies.

Because the first runtime collection reads only the previous 30 minutes, emit a fresh synthetic
session during acceptance. Confirm the durable job completes, the Runtime page displays the agent,
model, and tool sequence, coverage is explicit, and every retained activity reports
`content_policy=metadata_only`. The production reference pass is recorded in the
[Azure Foundry AIDR acceptance](../handoffs/2026-09-14-azure-foundry-aidr-production-acceptance.md).

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
- Entra admin-consent callback:
  `https://denali.example.com/api/v1/connections/entra/setup/callback`;
- Azure Repos OAuth callback:
  `https://denali.example.com/api/v1/connections/azure-repos/oauth/callback`;

Set `DENALI_GITHUB_CALLBACK_URL`, `DENALI_ENTRA_CALLBACK_URL`,
`DENALI_AZURE_REPOS_CALLBACK_URL`,
`DENALI_WEB_URL`, `CLERK_AUTHORIZED_PARTIES`, and
`DENALI_CORS_ORIGINS` to the final values. The browser normally uses the same-origin proxy; CORS
remains restricted for diagnostics and controlled direct calls.

### Isolated Vercel preview environment

Do not point a Vercel preview using Clerk development keys at `denali-production`. Create an
isolated hosted development stack named `denali-dev`:

1. Create a Neon branch and empty database named `denali-dev`, owned by a dedicated
   `denali_dev_owner` role. Collect pooled and direct DSNs that explicitly select the
   `denali-dev` database and that role; do not reuse the production owner DSN.
2. Create a Modal environment named `denali-dev`, then create a Secret named `denali-dev` inside
   it with those DSNs, the Clerk development `sk_test_...` key and matching development JWKS PEM,
   and the exact stable Vercel preview origin in `CLERK_AUTHORIZED_PARTIES`, `DENALI_WEB_URL`, and
   `DENALI_CORS_ORIGINS`. If the Clerk session template includes an `aud` claim, set
   `CLERK_AUDIENCE` to that exact value as well.
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

Use one stable Vercel alias as the review entrypoint for authenticated previews. Point that alias
at the PR deployment currently under review instead of adding every generated branch URL to Clerk
or Modal. The current review alias is
`https://denali-dev-preview-transilience-a55654db.vercel.app`. Configure that exact origin in the
Clerk development instance and in `CLERK_AUTHORIZED_PARTIES`, `DENALI_WEB_URL`, and
`DENALI_CORS_ORIGINS` in the `denali-dev` Modal Secret, then redeploy `denali-dev`. Do not use a
wildcard authorized party or CORS origin. Moving the alias to a new PR deployment does not require
changing those values.

## 5. Acceptance and operations

For two separate Clerk organizations, verify:

1. organization switching changes `/api/v1/context` and all displayed data;
2. a member can read but receives `403` for every mutation;
3. an admin can update governance and operate connections;
4. AWS, Azure, Microsoft Entra, GCP, Google Workspace, GitHub, and Azure Repos complete their
   hosted setup, callback, validation, disable, and delete flows; collection is accepted separately
   for every enabled collection;
5. opted-in AWS AgentCore and Azure Foundry runtime planes produce metadata-only sessions with
   explicit coverage, and retained evidence contains no prompt, response, system-instruction, tool
   argument, or tool result fields;
6. killing an API container does not stop an already spawned validation or collection worker;
7. Neon restore procedures have been exercised on a non-production branch.

Monitor Vercel external-origin errors, Modal function failures/timeouts, Neon connection and
storage metrics, and validation jobs that remain `running` beyond their lease. Logs may contain
tenant UUID, connection UUID, and job UUID, but never Clerk tokens, provider tokens, setup codes,
private keys, or database credentials.
