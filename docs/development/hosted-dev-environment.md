# Hosted development environment

This is the operator and coding-agent runbook for Denali's shared hosted development environment.
Use it for Vercel previews, the stable development domain, authentication failures, Modal
development deployment, and Neon development data. It does not authorize a production change.

## Live environment contract

| Boundary | Development value |
| --- | --- |
| Git branch tracked by Vercel | `dev` |
| Stable web entrypoint | `https://denali-dev.transilience.cloud` |
| Stable review alias | `https://denali-dev-preview-transilience-a55654db.vercel.app` |
| Clerk | Transilience development instance |
| Modal environment/app/core Secret | `denali-dev` / `denali-dev` / `denali-dev` |
| Modal provider Secret | `denali-github-provider` in `denali-dev` |
| Stable Modal API origin | `https://transilience-denali-dev--denali-dev-api.modal.run` |
| Neon | Isolated `denali-dev` branch/database |

The request path remains browser -> Vercel -> same-origin `/api/*` rewrite -> Modal FastAPI ->
Neon. The browser must never call Modal or Neon directly. Development identity, application
secrets, and data must never cross into production.

Vercel receives only these two values for Preview and the custom `denali-dev` environment:

```text
VITE_CLERK_PUBLISHABLE_KEY=<matching Clerk development pk_test_... key>
MODAL_API_ORIGIN=https://transilience-denali-dev--denali-dev-api.modal.run
```

The publishable key is public configuration, but keep the Clerk secret key, JWT PEM, Neon DSNs,
and provider credentials in Modal Secrets. Never create a `VITE_*` secret.

## Clerk development contract

The Clerk development instance is shared. Its `__session` custom claims must match production:

```json
{
  "isMfa": "{{user.two_factor_enabled}}",
  "orgRequiresMfa": "{{org.public_metadata.requireMfa}}"
}
```

Do not add an `aud` claim. `CLERK_AUDIENCE` is intentionally absent from the `denali-dev` Modal
Secret. Adding an audience for one application makes shared development tokens incompatible with
other applications using the instance. If the claims change, save them in Clerk and sign out and
back in at the stable development domain so Clerk issues a fresh token.

Clerk development users and Organizations are separate from production. A successful production
login does not create the same user, Organization, membership, or Denali tenant mapping in
development.

## Modal development contract

The `denali-dev` core Secret contains the development Clerk backend configuration and isolated
Neon DSNs. These non-secret routing values must stay synchronized:

```text
CLERK_AUTHORIZED_PARTIES=https://denali-dev.transilience.cloud,https://denali-dev-preview-transilience-a55654db.vercel.app,http://localhost:3000,http://localhost:3001
DENALI_WEB_URL=https://denali-dev.transilience.cloud
DENALI_CORS_ORIGINS=https://denali-dev.transilience.cloud,https://denali-dev-preview-transilience-a55654db.vercel.app,http://localhost:3000,http://localhost:3001
```

Use exact origins without paths or trailing slashes. Do not add wildcards or every generated
Vercel deployment URL. Point changing previews at the stable review alias instead.

The same Secret also requires these values, but their contents must never appear in documentation,
logs, screenshots, commits, PR descriptions, or Vercel:

```text
CLERK_SECRET_KEY
CLERK_JWT_KEY
DENALI_DSN
DENALI_MIGRATION_DSN
```

`DENALI_DSN` uses the pooled Neon endpoint. `DENALI_MIGRATION_DSN` uses the direct endpoint and is
used only by the explicit migration function. Both must identify the isolated development
database and role, never production.

For the opt-in shared-connections pilot, the dev deploy supplies the public platform origin
through a deployment-scoped Modal configuration Secret on every Denali function. Keep the
`DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN` deploy-shell value pointed at the isolated platform
development API. The existing core Secret holds `DENALI_PLATFORM_MACHINE_SECRET_KEY`; do not
overwrite it just to add the public origin. Every function mounts this configuration object so
the dependency graph remains stable when Modal re-imports the module inside containers and
background workers import the API module.

## Automatic development deployment

A push to `dev` starts the **Deploy Modal development** GitHub Actions workflow. It requires the
exact remote `dev` SHA, runs the complete Python/PostgreSQL/frontend verification gate, enters the
GitHub `denali-dev` environment, checks configuration, applies migrations, deploys the API and
workers, and runs direct Modal plus same-origin Vercel smoke checks. Its concurrency group cancels
an older development deployment when a newer `dev` revision arrives.

The workflow uses repository `MODAL_TOKEN_ID` and `MODAL_TOKEN_SECRET` secrets only to authenticate
the Modal deployment. Clerk, Neon, and provider values remain in Modal Secrets.

A Modal Secret edit does not update an already warm API container and does not create a Git push.
After changing Clerk, Neon, CORS, canonical URL, or provider configuration, manually dispatch
**Deploy Modal development** from the `dev` branch and provide the full SHA currently at
`origin/dev`. The workflow rejects a different branch or stale SHA.

## Emergency local development deployment

Use the local helper only when GitHub Actions is unavailable. Run it from the checkout whose code
is meant to become the shared development backend. The helper rejects dirty worktrees and any
revision that does not exactly match `origin/dev`; invoking its path from another branch does not
bypass this guard.

The normal shared baseline is the current remote `dev` branch. A disposable worktree makes the
source revision explicit:

```bash
git fetch origin --prune
deploy_worktree=$(mktemp -d /tmp/denali-dev-deploy.XXXXXX)
git worktree add --detach "$deploy_worktree" origin/dev
(
  cd "$deploy_worktree"
  ./scripts/deploy_modal_dev.sh
)
git worktree remove "$deploy_worktree"
```

Before running this sequence, confirm the intended `origin/dev` SHA and record it in the handoff.
If `dev` is expected to mirror `main`, verify the SHAs match. Do not deploy a closed PR or unrelated
feature branch into the shared environment. Backend feature work that must run before merge should
use an explicitly isolated Modal environment/app rather than silently replacing the shared
baseline.

The helper runs the migration function under the repository advisory lock and then deploys the
API and workers. The expected stable API origin is the non-`-dev` URL shown above; the temporary
`...api-dev.modal.run` URL printed by `modal run` is not a Vercel target.

Redeploy Vercel only when a Vercel variable or frontend revision changes. A Modal Secret-only
change needs a manually dispatched Modal development workflow, not a Vercel rebuild.

## Verification after a change

Check the boundaries in this order:

1. Direct Modal `GET /healthz` returns `200` and `status=ready`.
2. `GET https://denali-dev.transilience.cloud/api/healthz` returns `200` through Vercel.
3. An unauthenticated `GET /api/v1/context` returns `401`.
4. A signed-in user with an active development Organization receives `200` from
   `/api/v1/context`.
5. Reload the application and confirm inventory, findings, connections, issues, detections,
   activity, coverage, and vulnerability requests complete without authentication errors.
6. Switch between two development Organizations when tenancy is in scope and confirm their Denali
   tenant UUIDs and data differ.

Do not report success from a rendered shell alone. Inspect the authenticated API responses after
the final Modal deployment. Browser UI can briefly retain an earlier error while retry requests
are already succeeding; wait for polling to settle or perform one clean refresh before concluding
that the failure remains.

## Authentication troubleshooting

### `TOKEN_INVALID_AUDIENCE`

The Clerk development session template still contains an application-specific `aud`, or the
browser is using a token issued before that claim was removed.

1. Confirm the development `__session` claims match the JSON above and contain no `aud`.
2. Do not add `CLERK_AUDIENCE` to Modal.
3. Save the Clerk change and sign out and back in at the stable development domain.
4. Retest `/api/v1/context`.

### `TOKEN_INVALID_AUTHORIZED_PARTIES`

The token's authorized party is not in the Modal allowlist, or the Modal API container has not
loaded the updated Secret.

1. Confirm the request uses the stable development domain or stable review alias.
2. Update `CLERK_AUTHORIZED_PARTIES`, `DENALI_WEB_URL`, and `DENALI_CORS_ORIGINS` together using
   the exact values above.
3. Redeploy `denali-dev` from the intended clean revision.
4. Retest the authenticated context endpoint and wait for application polling to settle.

### `DEPLOYMENT_NOT_FOUND` or a Vercel login page

Confirm `denali-dev.transilience.cloud` is attached to the Denali Vercel project and assigned to
the custom `denali-dev` environment tracking `dev`. If Vercel requests ownership verification,
add the exact TXT record it supplies. Deployment protection can separately require Vercel login
for generated preview URLs; the stable custom development domain is the normal shared entrypoint.

### Post-authentication application is blank or unavailable

Check the environment pair as a unit:

- the frontend uses the Clerk development publishable key;
- Vercel rewrites to the stable `denali-dev` Modal origin;
- Modal uses the matching Clerk development secret/JWKS;
- the active Clerk Organization exists in development; and
- Modal connects only to the Neon development database.

Do not work around an instance mismatch by routing a development token to production or by copying
production secrets or data into development.

## Handoff requirements

Record the Vercel deployment/alias, Clerk instance, Modal environment/app, deployed source SHA,
Modal deployment URL, Neon environment name, and each smoke-check result. List configuration names
without values and never include tokens, keys, DSNs, passwords, or private keys. State explicitly
whether any PR is unmerged and whether only development—not production—was deployed.
