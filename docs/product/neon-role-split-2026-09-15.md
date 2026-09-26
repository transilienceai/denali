# Neon runtime and migration role split — 2026-09-15

This record covers the production Neon least-privilege role split. It contains role names,
privilege outcomes, and bounded schema counts only. It excludes DSNs, hosts, passwords, database
addresses, and row data.

## Environment and pre-change state

- Date and UTC window: 2026-09-15 21:55–22:02 UTC
- Operator: KK Mookhey / Codex
- Database: `denali`
- Applied migrations: 20; latest `020_azure_foundry_agent_runtime_activity.sql`
- Application tables in `public`: 33
- Modal environment and Secret: `denali-prod` / `custom-secret`

Before the change, both `DENALI_DSN` and `DENALI_MIGRATION_DSN` authenticated as
`neondb_owner`. That role owned all 33 application tables, could create in `public`, and had
`CREATEROLE`, `CREATEDB`, `REPLICATION`, and `BYPASSRLS` attributes. The two settings were
distinct connection URLs but not distinct authorization boundaries.

## Applied boundary

- [x] Created login role `denali_runtime` with no superuser, role-creation, database-creation,
      replication, or RLS-bypass attributes.
- [x] Created login role `denali_migration` with the same elevated role attributes disabled.
- [x] Transferred the `public` schema and all 33 Denali application tables to
      `denali_migration`; provider-extension objects not owned by Denali were left unchanged.
- [x] Granted `denali_runtime` schema usage plus table CRUD, sequence use, and function execution.
- [x] Revoked `CREATE` on `public` from `PUBLIC` and `denali_runtime`.
- [x] Installed default privileges so future objects created by `denali_migration` grant only the
      required runtime access.
- [x] Rotated both credentials and updated only `DENALI_DSN` and `DENALI_MIGRATION_DSN` in the
      existing Modal Secret. No credential or DSN was printed or written to the repository.

## Verification

- [x] A fresh hosted connection using `DENALI_DSN` authenticated as `denali_runtime`.
- [x] The runtime role could read migration state and see all 33 application tables.
- [x] A runtime `CREATE TABLE` attempt failed with insufficient privilege and was rolled back.
- [x] The runtime role owns zero application tables and cannot create in `public`.
- [x] A fresh hosted connection using `DENALI_MIGRATION_DSN` authenticated as
      `denali_migration`.
- [x] The migration role owns `public` and all 33 application tables.
- [x] The migration role successfully created and dropped a transactional DDL probe, which was
      rolled back.
- [x] Both roles reported `superuser=false`, `createrole=false`, `createdb=false`,
      `replication=false`, and `bypassrls=false`.

## Activation boundary

The warm production API container initially predated the Secret rotation. It received an explicit,
temporary DML-only compatibility grant so requests could continue without restoring ownership or
schema privileges. Protected production deployments later replaced the Modal application from
merged `main`; deployment run
<https://github.com/transilienceai/denali/actions/runs/35235965881> succeeded at exact SHA
`6f147d2f18d461ec08d6612ff9d167a4718ed630`. A subsequent invocation of the deployed
`active_connection_status` function completed through the rotated runtime DSN and returned all 21
active connection states. The earlier fresh-container probe had already established that this DSN
authenticates as `denali_runtime` and cannot perform DDL.

On 2026-09-17 the temporary compatibility boundary was removed after the protected deployment and
rotated-runtime checks above. The migration role revoked only the explicit `SELECT`, `INSERT`,
`UPDATE`, and `DELETE` grants from `neondb_owner` across the 33 application tables. A post-change
query found zero remaining owner CRUD grants, retained runtime `SELECT` access to all 33 tables,
and reconfirmed that all application tables remain owned by `denali_migration`. The currently
deployed `active_connection_status` function then completed through `DENALI_DSN` and returned 21
connection rows across all seven P0 providers.

The signed-in Neon dashboard identity was also rechecked on 2026-09-17. It has a Neon organization
but no projects, so it cannot configure or inspect the production project's managed alerts,
point-in-time recovery, or restore branches. Those controls require a production-project invite or
a scoped Neon API credential from the project owner; database credentials do not grant control-
plane access.

## Result

- Database role split: passed
- Modal Secret rotation: passed
- Runtime DDL denial: passed
- Migration DDL capability: passed
- Fresh hosted-container verification: passed
- Production Modal replacement and rotated runtime activation: passed
- Obsolete owner CRUD compatibility grant removal: passed
- Neon managed backup/alert/restore controls: not covered by this record
