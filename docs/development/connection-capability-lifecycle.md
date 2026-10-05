# Connection lifecycle capabilities

The receiver adds explicit lifecycle actions for seven existing native providers
and the opt-in shared AWS pilot. Actions call the existing Denali handlers,
preserving provider onboarding protocols, Platform application entitlement and the
shared pilot organization allowlist. No customer grants, provider secrets, machine
grants, browser callbacks, or production settings change.

## Guarded actions

`POST /internal/v1/capabilities/connections/actions` accepts a discriminated JSON
body of at most 65536 bytes. Every action requires `expected_org_id` (the active
Clerk organization), `confirmed: true`, and an 8–128 character `Idempotency-Key`.
The receiver resolves the tenant from verified machine claims and current Clerk
membership, requires a current organization administrator, and checks the expected
organization. Unknown fields and query parameters are rejected.

| `action` | Additional fields |
| --- | --- |
| `create` | `connection`: existing provider-specific create model for AWS, Azure, Entra, GCP, GitHub, Google Workspace, or Azure Repos |
| `setup-launch` | `connection_id`, `provider`: AWS, Azure, Entra, GCP, GitHub, or Azure Repos |
| `setup-complete` | `connection_id`, `provider`; Azure/GCP require only transient `completion_code` (16–32768 characters), Azure Repos requires only `repository_ids` (1–500 UUIDs), Workspace accepts neither |
| `disable`, `delete` | `connection_id`, `confirmation_name`: exact current display name |
| `shared-create` | `connection`: existing bounded shared AWS create model |
| `shared-attach` | `connection_id`, `region`, `declared_scopes`: exact existing shared AWS permissions to attach to Denali |
| `shared-validate`, `shared-probe`, `shared-disable` | `connection_id`, `confirmation_account_id`: exact 12-digit AWS account; only `shared-probe` requires `region` |

Normal actions require downstream machine purpose `denali:write`. Disable, delete
and shared-disable require distinct purpose `denali:connections:destructive`, which
Platform issues only after corresponding optional destructive OAuth consent. A
normal write token cannot authorize these operations; a destructive token cannot
authorize ordinary writes. Browser session APIs retain existing administrator checks.
Delete requires prior disablement. Disable retains active validation and collection
safeguards. Neither operation revokes customer cloud permissions or deletes collected
evidence. GCP create retains the existing operator-side keyless principal provisioning.

Setup launch reuses tenant-bound, expiring, one-time state. GitHub and Entra finish
through existing callbacks and browser handoff, which cannot be called as MCP actions.
Workspace authorization remains an external super-administrator step followed by
explicit completion. Azure Repos completion selects only staged, unexpired candidates
and independently verifies every selected repository using the service principal.
Setup completion and AWS launch require a durable validation dispatcher before setup
state changes. The API never performs a customer cloud grant itself.

Migration 024 reserves an action durably before invoking any lifecycle handler. It
stores only tenant, actor, action, connection identifier, request hash, state, status
code and timestamps. It never stores input JSON, completion codes, state-bearing
links, commands, provider credentials, or provider results. A fresh success returns
`action`, `connection_id`, `status: completed`, `replayed: false`, and a redacted
connection, transient setup launch, normalized probe, or job acknowledgment where
applicable. Create/setup launch return 201; setup completion/shared validation return
202; other actions return 200.

A completed retry returns 200 with `replayed: true` and `previous_status_code`. It
does not repeat the handler or return the original one-time link. A new explicit
setup launch key can replace an expired link using the existing protocol. Pending
or failed claims return 409: a crash/timeout cannot cause automatic duplicate side
effects. Inspect the target before a fresh action. Actor, action or payload changes
under the same tenant/key return 409. Audit survives connection deletion. Provider
errors and input validation do not echo completion codes.

## Bounded reads

Reads require `results:read` and live membership, reject unknown/duplicate parameters,
and return `Cache-Control: no-store`.

| Named read | Parameters and projection |
| --- | --- |
| `connection-setup-status` | `id`: UUID; connection summary, explicit public onboarding identifiers, expiry/status, and at most 500 exact selected/candidate project, subscription, or repository identities |
| `connection-aws-template` | `id`: UUID; `media_type` and connection-specific YAML `template`, at most 131072 bytes |
| `shared-connections` | `limit`: 1–100 (default 20), `offset`: 0–100000; ID-ordered redacted page with `has_more` |
| `shared-aws-status` | `id`: UUID; redacted summary plus health, credential state, validation timestamp and durable job state/identifier/error classification |
| `shared-aws-template` | `id`: UUID; bounded YAML using the app-entitled bridge |

Templates are explicit customer-reviewable grant plans. They can contain the existing
connection external ID, which stays transient and never enters the action ledger. No
read returns opaque configuration, raw validation/provider payloads, state digests,
PKCE, secrets, or short-lived credentials. The shared upstream list uses the existing
pilot API; the MCP response is bounded without altering that API contract.

No general connection update or enable endpoint exists in the current UI. Explicit
setup completion/selection represents the existing configuration workflow; there is
no arbitrary configuration update or provider API forwarding.

## Release acceptance

Required gates: Ruff, full Python tests, PostgreSQL tenant/actor/concurrent reservation
tests, Modal compilation, and frontend production build. After review/merge, hosted
acceptance requires current-admin, removed-member, wrong-purpose, absent destructive
consent, organization-switch, replay/conflict, one-time callback and two-organization
checks through the deployed gateway. Every enabled provider needs hosted create →
setup/callback → validate → disable → delete. Mocks do not establish that acceptance.
This implementation does not authorize merge, deployment, provider/customer mutation,
new grants, or configuration changes. Disable the receiver via its existing machine-ID
configuration boundary if needed; applied migrations remain.
