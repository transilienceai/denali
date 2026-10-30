# Native Denali identifiers in Clerk: an explicitly enrolled six-connection pilot

This is a settings lookup change, not a credential migration or a change to cloud
access. The approved deployment manifest is NI-prod's existing six native Denali
connections. Their IDs and Clerk organization ID are deployment configuration,
not constants, fixtures or sample customer data in this repository. All other
organizations/connections and all Platform-shared connections keep their existing
paths. No setup, validation, scan, collection, provider permission or IAM change
is part of publication or verification.

## Ownership and private format

Denali alone publishes `Organization.private_metadata.transilience_native_connections`.
It never writes Platform's `transilience_connections` namespace. Both publishers
patch only their own namespace and must preserve unrelated private/public data.
Native identifiers cannot be converted into Platform broker admission merely by
being listed in Clerk.

Version 1 has exactly `version`, `source_app_id` (`denali`), `environment`,
`organization_id`, `revision`, `published_at`, `expires_at` and `sources`. Sources
are provider-keyed arrays. Each record has exactly `id`, `binding_sha256` and
`settings`. The identifier projection is fixed and deliberately narrower than a
raw connection row:

| Provider | Stable settings eligible for the private projection |
| --- | --- |
| AWS | Role ARN, external ID, account/partition, role name, regions/coverage selector and exact selected-resource identifiers when present |
| GCP | Per-connection principal email/unique ID and selected project IDs |
| Azure | Client/service-principal IDs, tenant ID and selected subscription IDs |
| Entra | Client and tenant IDs |
| GitHub | App/installation/account IDs and exact repository IDs |
| Google Workspace | Service-account/OAuth client ID, domain and admin identity |
| Azure Repos | Client/tenant/organization identity and repository IDs |

The current six-ID pilot need not contain every supported category. A provider is
not admitted or made operational by an empty category. Required identifiers and
nonempty resource selections are checked before preflight can report ready.
Provider health is **not** required to be healthy and is never altered by this
change; an unhealthy/partial connection must remain represented honestly.

`project_native_settings()` and `native_binding_sha256()` in
`src/denali/integrations/native_connection_settings.py` are the canonical projection
and binding implementation used by both writer and consumer. Hash inputs include
the current server-resolved tenant/organization, connection ID, provider, native
credential type and projected settings. The consumer checks both this hash and
canonical JSON bytes against the current database projection, including value
types. Clerk booleans/floats cannot substitute for database integer identifiers.
Declared scopes remain live database authority and are never obtained from Clerk;
a scope-only edit therefore does not need an identifier refresh. Clerk cannot
retarget the connection, change credential type, add scopes or select another tenant.

Passwords, access/refresh tokens, private keys, raw source payloads, setup-state
hashes, PKCE verifiers, onboarding state and GCP operator credential profiles or
federation configuration are never projected. Native authentication still uses
the existing Denali-operated identity, provider trust and token flows. No
credential is copied to Platform or another application.

## Consumer and execution boundary

`get_connection_validation_target()` still performs the existing tenant-scoped
PostgreSQL read first and **closes that context before Clerk network access**.
For an active, explicitly enrolled native connection, it obtains the bounded
private snapshot from Clerk and overlays only matching stable identifiers.
Lifecycle, scopes, coverage plan, setup/onboarding data, operator-profile choices,
repository/project display metadata and durable job state remain database-owned.
Disabled connections retain their database lifecycle denial without requiring a
remote lookup.

The five existing identifier-changing setup methods (Azure completion, GCP
completion, GitHub installation return, GitHub completion and Azure Repos
completion) publish after their database commit and before the API's next consumer
read. This is limited to the enrolled org/ID while source is Clerk and publication
is enabled; no provider or health mutation is added. Normal successful setup does
not wait for the periodic tick. Their fresh read-only publication transaction can
wait up to three seconds for the ordinary tick's org lock, with the existing
five-second statement bound and no HTTP retry. Tick/manual/preflight keep immediate
try-lock behavior. A publication outage is fixed settings
unavailability, never a provider-credential failure. Validation itself only writes
health/evidence/timestamps and does not change the selected identifiers.

Publication happens after the durable write: a one-time callback capability may
already be consumed if Clerk then fails. The existing callback failure redirect or
fixed API error is retained; replay of that consumed callback is not promised. The
committed state remains intact, no validation job is created by publication, and
the normal fresh setup flow can resume after identifier publication recovers.

The shared getter covers the existing API setup/validation paths, durable native
validation and collection workers, runtime collection and internal native bridge
readers. Provider adapters, sessions, IAM, OAuth consent and broker dispatch are
not replaced. Local/operator CLI commands without a hosted connection reference
are not enrolled by this pilot.

The result is still a dictionary. Successful Clerk provenance is a non-enumerable
Python attribute on its dictionary subclass, never a dictionary key, API field or
provider payload. This lets the operator verification count actual consumer use
without serializing internal metadata. Existing public connection responses and
CLI/MCP receiver contracts are unchanged.

Version/org/environment/ID/provider/hash checks, strict field allowlists, response
size limits and a maximum 300-second lifetime fail closed. There is no stale cache
or fallback for an enrolled active connection. Direct API requests receive a fixed
503 `native connection settings unavailable`; workers retain their existing
sanitized failure handling. Another organization's settings or failures do not
change an unselected organization's native path.

Each selected active target resolution makes one Clerk GET. A normal publication
refresh or selected identifier write makes one GET plus one PATCH; provider-free verification resolves the six
targets and performs a final metadata GET. There is no process cache or HTTP retry.
Clerk latency, availability and rate limiting therefore become runtime dependencies
for the enrolled native path; their production workload impact still requires live
observation.

## Configuration (names only; no values belong here)

- `DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE=database|clerk`: compatible default
  `database`; Clerk is selected only for the explicit org and connection manifest.
- `DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS`: exactly one approved
  Clerk organization. No organization is inferred from an arbitrary oldest tenant.
- `DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS`: exactly six unique,
  canonical UUIDs. New connections stay on their existing path until separately
  reviewed/enrolled; changing this pilot's scope requires another decision.
- `DENALI_NATIVE_CONNECTION_SETTINGS_ENVIRONMENT`: the matching production or
  development environment. Configuration replay derives it from the recognized
  runtime Modal environment before falling back to the deploy-shell application
  selector, preserving the same anonymous configuration during remote re-import.
  The runtime Modal environment and Clerk key prefix must agree; selected native
  lookup/publication reject an unknown nonempty Modal environment.
- `DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED=true|false`: separate,
  default-false **deployment** selector for the 60-second refresh scheduler and
  manual publication permission. It does not select the native consumer. Deployment
  refuses source Clerk unless publication is enabled and exact-six pins are valid;
  this check uses a standard-library-only parser before Modal resources are built.
- The existing Denali-owned `CLERK_SECRET_KEY` is the native reader/writer's backend
  credential. An optional `DENALI_NATIVE_CONNECTION_SETTINGS_SECRET_KEY` may
  explicitly override it inside Denali only. These remain Modal secrets and never
  enter Vercel, browser/CLI config, metadata, session claims or another service.
  The shared connection reader's separate key behavior is unchanged.

Both protected deployment workflows forward GitHub variables for the publish
selector, source selector and org/six-ID manifest. Publish defaults false and
source defaults database. A protected exact-main workflow dispatch can therefore
stage publication and lookup independently without editing any provider secret.
Public deployment selectors/pins are replayed into workers. Existing core/provider
secret names and mount counts remain unchanged; no extra provider identity is
introduced. A source selection in GitHub variables is authoritative for that
deployment; a core Secret edit alone does not update warm containers.

## Operator functions: explicit, bounded and not public capabilities

All operator functions require Modal operator access. They are not browser,
CLI/MCP public tools, and none accepts an arbitrary provider URL or tenant UUID.
Use the exact already-approved Clerk organization as the expected-org argument.

1. `native_connection_settings_manifest(expected_clerk_org_id)` is unscheduled and
   read-only. It returns at most seven IDs/provider/type/lifecycle records to the
   authorized operator, never credential references or configuration. A count
   other than six is not a reason to silently widen the enrollment.
2. `preflight_native_connection_settings(expected_clerk_org_id)` performs only
   bounded read-only SQL and Clerk GET. It confirms the exact six current native
   bindings and the conservative combined private/public metadata budget of 8192
   bytes. Receipts contain counts, sizes, digests and saved-snapshot freshness,
   never raw identifiers/credentials. `ready` describes the proposed projection's
   completeness/capacity; `existing_snapshot_fresh` and `existing_binding_parity`
   separately describe what is already saved. No PATCH or provider call occurs.
3. `publish_native_connection_settings(expected_clerk_org_id)` requires the
   separate publication flag. It holds a PostgreSQL read-only repeatable-read
   transaction/advisory org lock through Clerk PATCH acknowledgement. The raw SQL
   selects only allowlisted identifier fields and reduces nested selections to
   IDs; it never recursively invokes the consumer. Initial preflight and staged
   source-database publication require all six complete bindings. In steady source
   Clerk operation, deleted/malformed rows are omitted independently; if the combined
   budget is exceeded, the largest whole record is omitted first, with provider/ID
   tie ordering. Lists are never truncated. Remaining valid records are refreshed;
   omitted IDs fail closed independently. Receipts distinguish missing, invalid,
   budget-omitted and published counts and mark partial publication honestly.
   Provider arrays replace in full, obsolete object keys are deleted, and unrelated
   namespaces are preserved. If even the empty native envelope cannot fit alongside
   other metadata, publication fails visibly. Reported headroom describes the current
   measurement and cannot reserve capacity against future Platform writes.
4. `native_connection_settings_tick` exists/schedules only when explicitly enabled:
   every 60 seconds, timeout 60 seconds, retries zero. Its fixed manifest is the
   same exact org/six IDs. Failures raise a fixed unconfirmed error so Modal records
   a failed run; partial acknowledged publication also raises a fixed partial-after-ACK
   error with counts-only logging. Neither condition starts an automatic retry.
   No failed publication extends expiry or changes provider health.
5. `verify_native_connection_settings_lookup(expected_clerk_org_id)` is unscheduled
   and read-only. After closing its raw SQL context, it resolves each enrolled
   target through the real repository consumer hook, without invoking a validator,
   collector, provider API, job or tenant creation. It returns source-use counts,
   binding parity, metadata size/freshness and existing health counts only. An
   active enrolled target not actually using Clerk makes verification fail.

Clerk PATCH has no compare-and-swap transaction with PostgreSQL. The org lock
serializes this publisher's normal calls, but a timed-out remote write can have an
unknown outcome. Treat it as unconfirmed, observe a later fresh revision, and do
not claim stronger ordering than the 300-second bounded lookup freshness. Database
identity/scopes and native provider authorization still fence every resolved target.

## Two-stage rollout and rollback (not performed by this source change)

1. Merge only after code review and required CI. Keep native source database and
   publication false. Confirm the exact environment/org and the existing six-ID
   manifest through the read-only operator functions. Do not validate unhealthy
   connections merely to make this migration look successful.
2. Run preflight before any metadata write. Review capacity, completeness and
   binding digest. Stop on a missing identifier, mismatched manifest, wrong
   environment or oversized metadata; do not truncate records or widen a grant.
3. Enable publication with source still database through the protected deployment.
   Observe two successful saved refreshes with distinct revision digests, fresh
   timestamps and unchanged binding parity. Native execution remains unchanged.
4. Separately set source Clerk for the same fixed manifest and deploy the exact
   reviewed main revision. Run the provider-free real-consumer verification; expect
   six source uses if all six lifecycle states are active and unchanged health
   counts. Confirm another organization/unselected connection still uses its old
   path. No scan/collection is needed for this acceptance.
5. If publication stalls, enrolled lookups become unavailable after expiry; they
   must not silently fall back. Roll back source to database through the protected
   deployment. Publication may also be disabled in a separate deployment. Do not
   delete provider roles/grants, native records, unrelated Clerk metadata or keys.

Offline and disposable PostgreSQL tests do not establish production activation,
live freshness or provider acceptance. Record exact released SHA, config names,
counts-only receipts and timestamps separately after operator execution.
