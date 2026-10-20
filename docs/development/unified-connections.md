# Unified connector experience

Denali has one provider picker, connection list, detail area and onboarding wizard.
The server catalog chooses the available adapter; the browser never treats a
Platform error as permission to create a native connection. The presentation is
**Grant access → Verify access → Collect evidence**. These stages are separate:
authorization is not validation, and successful validation is not collection or
a safety verdict.

## Ownership and compatibility

The browser uses the authenticated same-origin `/api` contract. FastAPI resolves
the active Clerk Organization to the Denali tenant UUID and enforces admin writes.
Platform calls are server-to-server, bound to that verified Clerk Organization
and the registered Denali machine application's exact entitlements.

Existing native connections keep their IDs, credential references, selections,
jobs, evidence and repair paths. There is no credential migration, bulk rewrite,
automatic reactivation or automatic scope expansion. Shared references use the
same validation/collection jobs and evidence pipeline through provider adapters;
a broker failure never invokes native credentials instead.

Connection responses preserve their existing fields and add `management_source`,
`platform_availability`, `platform_status_freshness`, `platform_last_checked_at`,
`platform_status_reason` and role-aware `actions`. The original health result is
historical validation evidence; Platform availability is a separate execution
gate. A `current` freshness value means the registry metadata was fetched for
this response, **not** that live provider access was revalidated. Remote provider
revocation is confirmed by the next bounded validation/read, not inferred from a
previous healthy badge. Native rows remain usable when Platform is unavailable.

The provider catalog is local policy, not an upstream availability probe. Shared
connection metadata is fetched once per list/detail presentation rather than once
per row. An unavailable shared source is visible and cannot validate/collect.

## Setup, return and organization switching

The React application and its request generation are keyed to the active
organization. Organization changes abort pending requests; a token obtained after
a change cannot dispatch the old organization's mutation. Status readers coalesce
overlapping refreshes, ignore abandoned results, poll pending durable jobs and
refresh on focus/visibility return. A newly attached local connection is selected
automatically.

GitHub and Azure Repos external returns have durable PostgreSQL onboarding
receipts. Denali stores a hash of a random expiring return capability, provider,
original tenant, request identity and optional original/local Platform source IDs.
Platform stores the originating app/org and a snapshot of the operator-registered
exact callback URL and authorization revisions, never a browser-supplied URL.
Each application registers its own host and path; Platform has no Denali route
default or legacy-origin fallback. For Denali, the one-time provider callback
returns to its registered same-origin callback, which consumes the Denali state
once and redirects with an opaque workflow ID. Authenticated resume reads are
tenant scoped: switching organizations cannot reveal or attach the original
organization's source. Relaunch invalidates the previous return capability.
Other provider setup/validation plans and durable jobs remain discoverable from
their server-side source inventory after navigation or reload; browser polling
does not own job correctness.

## Repository access review

GitHub has three distinct boundaries: provider installation access, Platform's
last verified available repository catalog, and Denali's immutable saved selection.
**Manage repository access** launches verified Platform setup and returns to this
Denali workflow. Merely refreshing the saved catalog does not reconcile an
external GitHub settings change. The verified list is also constrained by the
installer user's visibility; it does not promise every repository in an account.

For an existing shared source, setup sends Platform its existing connection UUID,
not a browser-supplied installation ID. Platform starts a fresh durable PKCE user
authorization directly against that stored installation; GitHub's already-installed
settings page is not a verified return path. Denali resolves a local attachment's
Platform UUID in the current tenant and rejects mismatched local/Platform IDs.
The onboarding receipt pins that Platform source and the original organization.
An existing disabled Denali attachment may be reviewed, but is never reactivated.
New-installation setup retains the original installation-then-OAuth sequence.

The UI distinguishes available, saved, selected, added and removed repositories.
Added repositories are unchecked. Changed immutable identity is removed from the
review selection. Admin confirmation is explicit. A different selection creates
a replacement attachment; the original is retained until separately disconnected.
Repeated attachment of the same immutable selection is idempotent despite mutable
metadata changes. Repository renames/transfers are not silently accepted as the
same boundary. Disable does not become re-enable through attachment.

Azure Repos similarly verifies an operator-admitted Microsoft tenant/application/
Azure DevOps organization, retains only exact repository/project identities and
requires explicit selection. OAuth PKCE user proof and independent application
read validation are separate. Denali receives opaque mediated reads, never the
provider access token. Every content read rechecks live repository identity;
source chunks are bounded and their final Git blob digest is verified.

## Local versus organization-wide lifecycle

**Disconnect from Denali** calls only the existing local connection lifecycle API.
It stops Denali use and retains collected evidence. Local delete is available
only after disable and respects active-job protections. It does not revoke grants
used by other applications.

**Disable access for all applications** is in a separate collapsed organization-
wide section, with confirmation and an impact explanation. Provider grants and
already issued short-lived leases require their separately documented cleanup/
expiration; a broker disable is not a promise of immediate credential revocation.

## Paired capability work

| Provider | Shared adapter coverage in this change | Important boundary |
| --- | --- | --- |
| AWS | All six native evidence scopes; selected (1–40) or automatic Regions; separate exact-resource path | Fresh per-service/per-Region leases; exact Lambda/IAM path cannot use broad leases |
| Azure | Existing selected-subscription metadata plus Foundry runtime activity | Fixed metadata-only broker queries; live component identity check; 24-hour runtime bound |
| Entra | Existing four evidence planes with native 168-hour activity lookback | Bounded pages, fixed projections and exact tenant binding |
| GCP | Existing keyless selected-project adapter retained | Saved project selection and original native paths unchanged |
| GitHub | Verified available catalog and explicit immutable selection review | No automatic repository expansion or webhook claim |
| Google Workspace | Existing admitted domain-wide delegation adapter retained | Domain/customer/principal binding; distinct validation and collection |
| Azure Repos | Verified setup, exact repository selection, validation and source collection | No PAT, persisted user token, arbitrary URL or provider write |

Exact-resource AWS uses a separate Platform binding, reader role, validation job
and audit record alongside broad account bindings. Its four pins are Zip Lambda
ARN, execution-role ARN, expected model ID/ARN and kind. Only `aws.code_to_cloud`
and the pinned Region are allowed. Platform verifies the role/account/selection
again before issuing the narrow lease. Its two successful read proofs authorize
selected evidence collection while account coverage remains partial. No account
discovery, source download, invocation or account-wide healthy claim is made.

These are implemented source contracts, not hosted acceptance evidence. Jira's
existing bounded reads are not a Denali connector and are not in this catalog.

## Migration, verification and rollout

1. Review and merge the paired Denali/Platform PRs separately. Do not deploy feature
   branches or Vercel previews to production. Review default-off provider flags,
   exact org/app entitlements and callback/target admission before any activation.
2. Merge and deploy Platform before Denali: the new shared Entra 168-hour window
   and optional repository return context require the compatible broker first.
   Apply forward-only Platform migrations 011–016 using its approved migration
   process and schema-016 runtime privilege manifest. They add durable return/
   semantic revisions, Azure runtime scope, Azure Repos, exact-resource AWS and
   app-independent exact callback registrations and existing-installation
   re-verification fences. Preserve the live provider flags
   and Secret names; omitted deployment-shell flags can disable existing pilots.
   Apply Denali migrations 027–028 under its existing advisory-lock migration
   function. Do not run migrations at API startup or change old migration files.
3. Configure environment-local provider identities only in Modal Secrets.
   `DENALI_PLATFORM_AZURE_REPOS_ENABLED` and `PLATFORM_ENABLE_AZURE_REPOS` default
   off; Azure Repos requires a separately approved target and operator application
   credential. `DENALI_PLATFORM_AWS_SELECTED_RESOURCE_ENABLED` and
   `PLATFORM_ENABLE_AWS_SELECTED_RESOURCE` default off. Existing pilot org allowlist
   and per-provider flags remain in force; flags do not grant entitlements.
4. Before deploying Denali, register its exact HTTPS callback endpoint through
   Platform's generic `scripts/register_connector_callback_modal.py` operator.
   The endpoint is `/api/v1/connections/onboarding/callback` on the approved
   environment-local Denali origin. There are no default app/machine/URL values.
   Preview is read-only; apply requires its reviewed expected-state digest. Keep
   dev/prod machines, Clerk, Modal Secrets, Neon branches and callbacks isolated.
5. Run all Python/Ruff/frontend gates and PostgreSQL integration tests. Test native
   and shared side by side, repository add/remove/rename/transfer and pagination,
   stale/duplicate/concurrent leases, callback replay, delayed responses, organization
   switching, reload/focus recovery, remote disable and broker outages. Demonstrate
   local disconnect does not call shared disable. Unit/mocked reads do not replace
   hosted validation or actual collection.
6. On exact merged revisions, record hosted create → grant/setup/callback → validate
   → collect → local disconnect → delete for every enabled provider, and test
   organization-wide disable separately on an isolated shared test source. Record
   actual evidence/coverage results, not only healthy badges. Use consenting test
   sources; never alter an existing customer's scope as an acceptance shortcut.
7. Only after every offered native capability and reconfiguration workflow has
   passed that acceptance should a reviewed policy change set Platform as the only
   route for **all new** connections. The catalog intentionally still reports
   `platform_only: false` and hosted/parity blockers. Existing organizations are
   not exempt from the future new-creation policy; existing bindings remain exempt
   from migration. No production activation is implied by merging this code.

Rollback is a reviewed revert of application policy/code from merged main with
the usual release process. Keep additive database migrations and existing native/
shared bindings; do not delete source records or revoke customer grants to roll
back a UI release. Disabling a new-creation flag must not rewrite old references.

The surface map classifies the catalog, receipts and Azure Repos setup/selection
APIs as authenticated browser handoffs. Existing validation, collection, job and
result names, permission scopes and legacy request shapes remain compatible.
The server's shared-AWS input additionally accepts exact-resource browser fields;
the currently pinned public gateway does not expose those new parameters. No
new CLI/MCP provider credential workflow or CLI release is introduced. Paired
private broker contracts live in Platform; public results adapter pins are unchanged.

## Connector UI loading and accessibility

Every provider panel must announce its initial access lookup immediately. Loading,
unavailable access, an empty approved list and a failed request are distinct states;
none may silently display an empty panel or create a native fallback. Selected-source
status checks and mutations have their own visible progress. Generation and unmount
guards discard late results before changing selection, starting a redirect or invoking
the parent attachment callbacks. Hosted organization changes still remount the app;
organization identity never moves into a browser-controlled API payload.

Provider tabs support arrow keys, Home and End and label their active panel. Evidence
choices pair a native checkbox with its visible label in a responsive two-column grid;
required bundles and saved defaults are unchanged. Existing authorized access is shown
first; an additional setup plan opens explicitly. Repository search and bounded pages
never select new repositories or discard selected entries outside the visible page.
Setup has a focused workspace rather than a duplicate connection detail beneath it.
Opening setup focuses its heading; closing it restores the Add/Manage opener, and
successful attachment focuses its detail region. Read-only detail actions use native
disabled-control semantics, not pointer-only CSS; setup links are hidden while evidence
disclosures remain readable. API authorization remains the security boundary.

Native creation selects the returned connection and closes setup in one navigation
transition; a second close action must not restore the previous query's connection.
During native AWS validation, an earlier result remains available as a collapsed,
timestamped historical result, never the outcome of the active retry. Durable running
state restores that distinction after reload. CloudFormation launches may wait for
role creation; manual validation checks current access without that wait. Setup must
preserve existing stacks and roles: use a separate stack and unique role name, and stop
to review a name collision rather than deleting an existing integration. A custom role
name also requires Denali's runtime caller policy to permit `sts:AssumeRole` for that
exact role ARN; ask the operator to review it before launch. Do not automatically widen
the caller policy. A previous credential pass is historical too: the current response
does not expose intermediate role proof while validation is running.
The top-level journey likewise keeps Verify current for every provider during a
validation rerun, even with earlier healthy or successful exact-resource proof.
Historical collection outcomes remain visible and are not reset by presentation.

Local visual QA uses `npm --prefix web run dev -- --host 127.0.0.1 --port 3104`, then
`http://127.0.0.1:3104/tests/fixtures/connector-ui.html`. The fixture uses synthetic
data, replaces **every** API method and blocks unsupported actions. It is dev-only,
localhost-only, and is not a production build entrypoint. Query options include
`provider=azure`, `source=native`, `empty=1`, `slow=1`, `error=1`, `provider_error=1`,
`member=1`, `validating=1` and `theme=light`. With a local server on port 3106, use
`http://127.0.0.1:3106/tests/fixtures/connector-ui.html?source=native&provider=aws&validating=1`
and close setup to inspect the native AWS detail. Only its synthetic validation state
is running; the earlier synthetic pass is retained to inspect the collapsed historical
result and current Verify journey. All other rows stay idle, and all API methods remain
synthetic or fail closed. These checks prove UI behavior, not hosted provider onboarding or
authorization. Native/shared scope and identity regression tests remain mandatory.

The October 2026 UI audit reproduced two root causes: text-input sizing was applied
to checkboxes, and asynchronous catalog/source/repository reads could leave empty
panels before later inserting the form. Local browser checks covered all seven
shared provider panels, all seven native forms at 320px, all seven native/shared
detail views, a 113-repository search with a selected result outside the filter,
empty access, slow catalog reads, retryable provider failure, and read-only members.
Azure cards measured 16px checkbox controls and 60px desktop rows; responsive cards
stayed within a 390px viewport. These are synthetic UI checks, not provider lifecycle
acceptance. No production connector, provider grant, saved selection or rollout flag
was changed during this audit.

GitHub collection recovery uses one wrapping action group: an eligible incomplete-only
retry is the primary action, while a full saved-selection collection is secondary.
Both controls have fixed-size icons and intrinsic desktop widths; narrow viewports
stack the controls with 44px minimum targets. Retry remains mounted but disabled
while collection runs, preserving its keyboard focus and preventing duplicate
submissions. Its associated description explains the affected count, retained
timestamps and the limits that may still leave coverage partial. Job IDs, retry
selection, durable dispatch, authorization and provider permissions are unchanged.
The recorded result is a separate status/count/time card, never a claim that
successful dispatch or healthy validation means complete evidence. Saved repository
identities remain fully inspectable in a bounded, keyboard-scrollable region.

The local fixture additionally accepts `collection=partial`, `collection=running`
or `collection=quota` to open a synthetic 113-repository GitHub detail directly.
Combine these with `source=native`, `member=1`, `disabled=1` and `theme=light` to
inspect action hierarchy, progress, permissions and responsive layout. Every API
method remains replaced: the preview cannot start a real collection or change
connections, repository selections or provider permissions.
