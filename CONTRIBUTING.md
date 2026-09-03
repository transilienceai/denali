# Contributing to Denali

Denali uses pull requests for every code, configuration, documentation, migration, and deployment
workflow change. Direct commits and pushes to `main` are not allowed.

## Start every change from current `main`

```bash
git fetch origin
git switch -c codex/<short-topic> origin/main
git status --short --branch
```

Human contributors may use another descriptive branch prefix. Coding agents use `codex/` unless
the user explicitly requests a different branch.

Do not begin edits when the worktree contains changes you do not understand. Preserve unrelated
work and ask before overwriting it.

## Prepare the local tools once

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[api,aws,azure,gcp,github,hosted,dev]'
npm --prefix web ci
```

Use `.venv/bin/python`, `.venv/bin/pytest`, and `.venv/bin/ruff` if the virtual environment is
not activated. No production secret is required to run the default local checks.

## Implement and verify

Keep one concern per PR. Add tests for changed behavior and update architecture or operations
documentation when a contract changes.

The standard local gate is:

```bash
.venv/bin/ruff check .
.venv/bin/pytest -q
.venv/bin/python -m py_compile modal_app.py
npm --prefix web ci
npm --prefix web run build
```

The PostgreSQL integration suite requires `DENALI_TEST_DSN`. See the
[change and release process](docs/development/change-and-release-process.md) for the additional
gates required by authentication, tenancy, migrations, durable work, and provider changes.

## Commit and open a PR

```bash
git diff --check
git status --short
git add <reviewed-files>
git commit -m "Describe the completed change"
git push -u origin HEAD
gh pr create --fill
```

Complete the PR template with the exact checks run, operational impact, and rollback plan. Wait
for required checks. Address review comments with additional commits on the same branch.

Creating a PR does not authorize its author or a coding agent to merge it. The user or designated
reviewer owns the merge decision.

## Deploy only after merge

Vercel may build feature-branch previews, but previews must use the isolated Clerk development,
`denali-dev` Modal, and Neon development environments.

Modal production deployment uses the **Deploy Modal production** GitHub Actions workflow. Supply
the full merged `main` commit SHA when dispatching it. The workflow re-runs the release gate,
requires the protected `production` environment, performs configuration and migration checks,
deploys, and verifies the direct and same-origin health boundaries.

Do not place production credentials in the repository or Vercel. GitHub's `production`
environment contains only the Modal deployment credential; the application secrets remain in
Modal Secrets.

Read the complete [change and release process](docs/development/change-and-release-process.md)
before a production-affecting change.
