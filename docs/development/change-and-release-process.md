# Denali change and release process

This is the executable delivery contract for human contributors and coding agents. It is written
so a contributor does not need prior knowledge of Git, Vercel, Modal, Clerk, or Neon to avoid an
unsafe release.

## 1. Invariants

1. `main` is protected. No direct commits or pushes, force pushes, or deletion.
2. Every change uses a branch and pull request.
3. CI must pass before merge. A failing gate is fixed, never bypassed.
4. Production deployment uses only the exact merged `main` commit.
5. Vercel Preview and backend development use Clerk development, `denali-dev` Modal, and the
   isolated Neon development database. They never use production identity or data.
6. Vercel Production receives only public client/routing configuration. Backend and provider
   secrets remain in Modal.
7. Database migrations are forward-only, numbered, immutable after application, and executed as
   an explicit pre-deploy step under the repository advisory lock.
8. A deploy is not complete until direct Modal health, the Vercel `/api` proxy, and the
   unauthenticated authorization boundary are verified.

## 2. Change lifecycle

### Prepare

```bash
git fetch origin
git switch -c codex/<short-topic> origin/main
git status --short --branch
```

- Use a narrow branch name and one concern per PR.
- Inspect repository instructions and the files in scope before editing.
- Stop if the worktree has unexplained changes or the requested action needs a secret, production
  approval, or provider-side permission that is unavailable.
- For a first checkout, follow the local tool installation block in `CONTRIBUTING.md`. Local
  verification uses `.venv`; it does not require or authorize access to production secrets.

### Implement

- Preserve the hosted architecture and security rules in `AGENTS.md` and ADR 0028.
- Add or update tests with the implementation.
- Add a new numbered SQL migration for schema changes; never edit an applied migration.
- Keep production-capable work durable: PostgreSQL job, idempotent claim, bounded lease, Modal
  worker, sanitized result, and safe retry.
- Update the relevant ADR/runbook when authentication, tenancy, persistence, callback, secret,
  provider, or deployment behavior changes.

### Verify

Run the smallest focused tests while developing, then the complete applicable gate before push.

| Change | Required before PR handoff |
| --- | --- |
| Documentation only | Link/path validation, `git diff --check` |
| Python/API | Ruff, focused tests, complete `pytest -q`, `py_compile modal_app.py` |
| Frontend | Frontend tests when present, `npm ci`, production build |
| Persistence/migration | Complete Python gate plus PostgreSQL integration suite using `DENALI_TEST_DSN` |
| Auth/tenancy | Invalid/expired token, origin, pending session, missing org, member/admin, org switch, cross-tenant tests |
| Durable worker | Duplicate, retry, failure, timeout, stale lease, API replacement tests |
| Provider | Unit/integration gate plus hosted create, callback/setup, validate, disable, delete; collection accepted separately |
| Deployment workflow | YAML parse, shell syntax, script guard tests, production command review |

Never claim that a hosted provider is accepted from mocks, configuration presence, or a green
connection badge alone.

### Commit and PR

```bash
git diff --check
git status --short
git add <reviewed-files>
git commit -m "Describe the completed change"
git push -u origin HEAD
gh pr create --fill
```

- Fill in every applicable PR checklist item.
- Include exact test results, migrations, secret/configuration names without values, deployment
  impact, manual acceptance, and rollback.
- Keep secrets, tokens, DSNs, passwords, callback codes, and private keys out of commits, PR text,
  screenshots, logs, and fixtures.
- Do not merge merely because checks pass. The user or designated reviewer decides when to merge.

## 3. GitHub repository controls

The `main` branch protection/ruleset must require:

- changes through a pull request;
- the `verify` CI status check and an up-to-date branch;
- resolved review conversations;
- protection for administrators;
- no force pushes and no branch deletion.

A formal approving review may be added when a second reviewer is available. Until then, PR use,
required CI, conversation resolution, and the explicit user-owned merge decision remain mandatory.

The GitHub environment named `production` must:

- allow deployment only from protected branches;
- contain `MODAL_TOKEN_ID` and `MODAL_TOKEN_SECRET` as environment secrets;
- use required reviewers when the team has an independent release approver; and
- never contain Neon, Clerk, or provider application secrets.

## 4. Preview and production environments

| Surface | Preview/development | Production |
| --- | --- | --- |
| Vercel | Feature branch/Preview | Merged `main` |
| Clerk | Development instance | Production instance |
| Modal environment/app | `denali-dev` / `denali-dev` | `denali-prod` / `denali-production` |
| Neon | Isolated `denali-dev` branch/database | Production database |
| Provider credentials | Development provider applications/identities | Production provider applications/identities |

Never point a preview at the production Modal origin or database. A preview URL changing does not
justify adding wildcards to Clerk authorized parties or CORS; use a stable branch alias.

## 5. Backend production deployment

### Normal path

1. Merge the reviewed PR after `verify` passes.
2. Copy the full commit SHA now at `main`.
3. Open GitHub Actions → **Deploy Modal production** → **Run workflow** on `main`.
4. Enter the exact full merged SHA.
5. Approve the protected `production` environment when required.
6. The workflow independently checks out that SHA, re-runs the release gate, runs Modal combined
   configuration status, applies pending migrations, prints non-sensitive database migration
   status, deploys the API/workers, and runs production smoke checks.
7. Record the workflow URL, commit SHA, migration version, health results, operator, and time in
   the PR or release record.

The GitHub workflow is the normal production interface. A coding agent must not deploy merely
because it has local Modal credentials.

### Required smoke checks

- Direct Modal `/healthz` returns `200` and `status=ready`.
- `https://denali.transilience.cloud/api/healthz` returns `200` through Vercel.
- Direct unauthenticated `/v1/context` returns `401`.
- For auth, callback, or provider changes, complete the relevant authenticated/manual acceptance
  without exposing tokens or secrets.

### Emergency local path

Use only when GitHub Actions is unavailable and the user explicitly authorizes an emergency
production deploy. The checkout must be clean `main` and exactly match `origin/main`:

```bash
git fetch origin main
git switch main
git pull --ff-only origin main
scripts/deploy_modal_prod.sh --confirm-production
```

Record why the protected workflow was unavailable and attach the same verification evidence. The
flag is not a bypass: the script rejects feature branches, dirty trees, and stale `main`.

## 6. Rollback and failed releases

- Stop on a failed configuration check, migration, build, deployment, or smoke check.
- Do not run a second ad hoc deployment with uncommitted edits.
- Application rollback means redeploying a previously reviewed, known-good commit through the
  protected workflow.
- Do not reverse or edit an applied SQL migration. Add a forward corrective migration.
- Do not switch production Vercel to `denali-dev`, reuse development Clerk keys, or point the
  production API at the development database as a recovery shortcut.
- If a provider secret is invalid, restore the prior Modal Secret version/value through the
  operator-controlled secret process and redeploy the last known-good commit.

## 7. Agent handoff format

Every coding-agent handoff states:

- branch and PR URL;
- commits added;
- files/contracts changed;
- tests run with pass/fail counts;
- migrations and configuration names affected, without secret values;
- preview or production actions taken;
- remaining manual acceptance and blockers; and
- whether the PR is unmerged, merged, or deployed.

Silence never implies a merge or deployment. If either action was not explicitly performed, say
so.
