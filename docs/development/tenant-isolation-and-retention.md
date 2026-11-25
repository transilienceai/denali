# Tenant isolation and evidence-history retention

This runbook separates database integrity, application authorization, and historical
retention. It does not authorize a production migration, a collection, a connection
change, or deletion. Every release still follows the [change and release
process](change-and-release-process.md).

## Scope of the first hardening release

- Keep the shared-database, shared-schema topology and the existing verified
  Clerk Organization -> `denali_tenant.id` mapping.
- Strengthen relationships between tenant-owned records with composite foreign
  keys. A valid record ID from another tenant must not be a valid reference.
- Qualify evidence joins by tenant as well as ID, including on a legacy database
  that has not yet received the new constraints.
- Provide an explicitly tenant-scoped, read-only retention report. A report is
  not an executable deletion plan and does not claim bytes will be reclaimed.
- Keep every table, existing connection, provider identity, repository selection,
  evidence record, API route, and public CLI/MCP contract.

This release does **not** enable PostgreSQL row-level security (RLS), purge rows,
repair worker leases, or create a retention schedule.

## Integrity and migration acceptance

The database must reject a cross-tenant child/parent reference, including when the
child's `tenant_id` is reassigned. Nullable references must retain their tenant
when a parent is deleted: `ON DELETE SET NULL` must clear only the nullable ID,
not the tenant column. Existing cascade/restrict behavior remains intentional.

Local Compose and import tests can use a configured tenant UUID without Clerk.
Do not add blanket `denali_tenant` foreign keys that silently remove that mode.
This is distinct from enforcing equality between two existing tenant-owned rows.

Before approving a hosted migration:

1. Run the full PostgreSQL gate on a disposable database, both from an empty
   schema and from the previous migration version with representative evidence.
2. Verify that historical cross-tenant references fail migration rather than
   being reassigned, silently removed, or hidden. Do not bypass this failure.
3. Run a bounded read-only integrity preflight in the target environment. Keep
   aggregate counts only; never export customer evidence or credentials.
4. Review affected table sizes, migration lock behavior and the protected release
   window. A timeout or constraint failure stops deployment; it is not permission
   to remove a constraint or delete offending records.
5. After the approved protected deployment, verify invalid references are rejected
   in the isolated development environment and perform non-mutating hosted
   authorization/organization-switching acceptance. Never inject invalid records
   into production to test rejection.

Application rollback must remain compatible with the stronger constraints. Do
not reverse an applied migration or weaken constraints to make older code work;
use a reviewed forward correction when needed.

## Read-only retention report

The report is an operator diagnostic, not a browser or MCP operation. An explicit
internal tenant UUID is appropriate only here because the operator already has
database authority. It must never become a client-controlled tenant selector on
an authenticated product route.

Run the report in an already authorized environment with `DENALI_DSN` supplied
securely. Do not paste a DSN into chat, logs, shell history, or a report. Do not
run migration, validation, collection, or refresh helpers to obtain the report.

```bash
python -m denali.store.retention --tenant-id INTERNAL_TENANT_UUID --keep-days 90
```

The tenant UUID must come from an independently verified organization mapping,
not from guessing an organization's name. `--keep-days` is explicit: 30, 90 and
180-day reports are useful sensitivity comparisons, **not approved retention
policies**. The report uses a bounded repeatable-read, read-only transaction and
returns aggregate metadata without provider payloads, scopes or source content.

Interpret candidate counts conservatively. They mean "older records left for
retention review after the implemented protections," not "safe to delete now."
Counts cannot be converted directly into reclaimed disk bytes, Neon billing
savings or a backup-retention change.

### State that must survive retention

| State | Why it is not an ordinary old log |
| --- | --- |
| Queued/running jobs and resumable checkpoints | A worker or durable scheduler may still need them. |
| Latest terminal job per connection/kind | Status and GitHub incomplete-only retries use the latest recorded result. |
| Successful AWS/Azure runtime watermark jobs | Collection cursors are currently derived from safe successful job results. |
| Gateway action/audit references | Removing idempotency history can make a previously used key execute again. |
| Latest coverage per tenant/connector/connection/plane/scope | An inactive scope's only current result can be old. Keep timestamp ties conservatively. |
| Runs referenced by observations, assertions, relationships or activity | They are evidence provenance, even where references are not enforced by foreign keys. |
| Runs needed by retained jobs | Retry/status/checkpoint state may still refer to earlier evidence. |
| Finding, vulnerability and scan observations | Run deletion can cascade into evidence still used by the application. |

Keep canonical inventory, relationships, findings, issues, activity, detections,
governance, provider configuration and audit tables outside an initial history
purge. A successful collection does not make prior evidence disposable.

## Before any actual cleanup implementation

A later reviewed PR and explicit operational approval must establish:

1. **Policy:** approved retention by evidence class and tenant, legal/incident
   holds, offboarding rules, and audit/idempotency guarantees. Do not choose one
   blanket age threshold for all tables.
2. **Recovery:** verified backups and a restore drill with agreed recovery
   objectives. A provider's advertised backup feature is not a tested restore.
3. **State separation:** preferably move runtime watermarks and reusable GitHub
   checkpoint identity into explicit durable state before pruning the jobs that
   currently carry them.
4. **Dependencies:** preserve latest scope results, live observations, retained
   job references and both foreign-key and semantic provenance references.
   Unknown schemas, new referencing tables or malformed checkpoints fail closed.
5. **Execution:** bounded tenant-scoped batches, concurrency protection against
   ingestion/retry, revalidation at execution time, an auditable dry-run-to-apply
   boundary, and no provider calls or connection changes.
6. **Acceptance:** compare inventory, evidence links, latest coverage including
   original timestamps, job status, cursors, retry behavior and idempotency before
   and after on a disposable/restored database. A high deleted-row count is not
   proof of correctness.

Do not `DELETE` old `collection_run` rows based on age alone: cascades can remove
coverage, finding observations, vulnerability observations and scan records.
Expired onboarding state also requires a separately approved policy rather than
being bundled into evidence cleanup.

## Expired worker leases

The report may count running jobs whose leases have expired. This is a diagnostic
signal, not permission to delete the job, force a successful result, reset a
checkpoint or start another collection. Investigate worker termination, provider
timeouts and scheduler eligibility separately. Any recovery must preserve the
existing job's evidence, tenant boundary and last safe cursor, and use a reviewed
durable lifecycle transition.

## Separate RLS rollout

Tenant-aware SQL and composite foreign keys are defense in depth, not RLS and
not a claim that all possible access paths have been proven safe. A later RLS
release must include:

- A central transaction boundary that binds only a verified tenant using
  transaction-local state, with deny-by-default behavior when no tenant is bound.
  Pooled connections must not retain tenant context after commit, rollback or
  failure.
- Separate, explicitly privileged scheduler/operator paths for bounded global
  enumeration and the registry, followed by tenant-bound worker execution.
  Do not make browser/MCP traffic use a bypass role.
- A non-owner runtime role without `BYPASSRLS` or schema-owner privileges, plus
  reviewed `USING` and `WITH CHECK` policies. Table owners normally bypass RLS;
  enabling a policy alone does not establish enforcement.
- Coverage for every tenant-owned table, JSON-backed lookup, callback, job claim,
  retry, ingestion, evidence reconciliation and resource-write approval path.
- PostgreSQL tests for absent/spoofed context, cross-tenant reads and writes,
  organization switches, pooled connection reuse, duplicate dispatch, stale
  leases, worker replacement and local Compose compatibility.
- Isolated hosted development acceptance for schedulers, callbacks, validation,
  collection and result reads before a separately approved production rollout.

See [ADR 0028](../architecture/0028-hosted-multi-tenant-runtime.md) for the existing
trust boundary and [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
for database policy semantics.
