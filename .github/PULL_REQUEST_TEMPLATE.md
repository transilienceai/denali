## Outcome

<!-- What user-visible or operational outcome does this PR deliver? -->

## Scope

<!-- Key files/contracts changed. Keep one concern per PR. -->

## Verification

- [ ] `git diff --check`
- [ ] Ruff
- [ ] Python tests
- [ ] PostgreSQL integration tests, or not applicable
- [ ] Frontend tests/build, or not applicable
- [ ] Shell/YAML validation, or not applicable
- [ ] Hosted/manual acceptance recorded, or not applicable

Exact commands and results:

```text

```

## Security and tenancy

- [ ] No secret, token, DSN, password, callback code, private key, or customer credential is
      committed, logged, or included in screenshots.
- [ ] Tenant-owned reads and writes remain scoped by the server-resolved Denali tenant UUID.
- [ ] API authorization remains authoritative; frontend role checks are presentation only.
- [ ] Provider callbacks use verified, expiring, one-time stored state.
- [ ] Not applicable; this change cannot affect security or tenancy.

## Persistence and durable work

- [ ] New schema work uses a new numbered migration; applied migrations were not edited.
- [ ] Work that can outlive an HTTP request uses a durable PostgreSQL job and Modal worker.
- [ ] Not applicable.

## Deployment impact

- Target environments:
- Configuration names added/changed (never values):
- Migration version:
- Manual acceptance required:

## Rollback

<!-- Application rollback or forward-fix plan. Never propose reversing an applied migration. -->

## Release state

- [ ] PR only; not merged and not deployed
- [ ] Merge requested explicitly by the user/reviewer
- [ ] Production deployment requested separately after merge
