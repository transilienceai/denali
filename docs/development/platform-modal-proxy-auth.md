# Development shared-broker Modal authentication

This is a focused backport to development source
`79c09fadd5306493e583dcce3726c823d0350e65`, preserving its 28 branch-specific
commits. It adapts only the applicable authenticated-transport changes reviewed
in production-targeted [PR #131](https://github.com/transilienceai/denali/pull/131)
at `e2c79d3eb50cac7bf0a105bc00cd1558eb1eaa9f`. It does not merge `main` into
`dev` or introduce main's newer connection features.

The existing shared AWS, GitHub, Azure and Entra broker calls retain their Clerk
machine bearer and tenant/entitlement behavior, with two additional server-held
headers: `Modal-Key` and `Modal-Secret`. Their values come only from the
environment-local `denali-platform-modal-proxy` Secret, containing
`DENALI_PLATFORM_MODAL_PROXY_KEY` and `DENALI_PLATFORM_MODAL_PROXY_SECRET`.
These are Modal proxy tokens, not Modal API credentials or customer credentials.
Incomplete/malformed pairs and wrong or unknown remote environments fail before
Clerk token minting. Headers are sent only to the fixed corresponding Platform
origin; provider requests and Clerk requests do not receive them.

Every existing function that imports the shared client mounts this dedicated
Secret when the deployment's shared broker origin is configured. The origin is
replayed into remote containers; an explicit empty value prevents a stale core
Secret from enabling the bridge during remote re-import. A dark deployment has
no new named Secret dependency. Both local and remote graphs keep the existing
core, provider, Shasta and deployment configuration dependencies.

The private legacy AWS metadata snapshot publisher uses the same authenticated
client and validates its configuration before reading its snapshot. The private
AWS verification operator also mounts the caller-owned proxy Secret. Neither
operator is run by this change. Development's existing AWS/GitHub broker
entitlement behavior and Microsoft-only organization admission remain unchanged.

## Scope differences from main

This development baseline does not implement Clerk connection-settings lookup,
the native Clerk metadata publisher, shared Google Workspace, shared Azure
Repos, or resource write leases. None are added here. Native AWS/GCP/GitHub,
Microsoft, Azure Repos and Workspace provider authentication stays as defined
by this branch. Its existing shared GitHub setup delegates the installation
handoff to Platform, and its shared Microsoft handoffs use the broker response.
It does not contain main's newer explicit shared GitHub existing-installation
or shared Azure Repos callback URL validators, so those changes are not ported.
Provider callback registrations and the broker's public gateway routing are
managed in the paired Platform rollout; native Denali callbacks do not change.

## Delivery and verification

Use a normal reviewed PR targeting `dev`, followed by its protected
**Deploy Modal development** workflow. Keep the exact `origin/dev` revision and
`refs/heads/dev` guards in `scripts/deploy_modal_dev.sh`; do not deploy this
feature worktree directly or copy all production source into development.

Focused tests cover the fixed destination and retained bearer, missing/invalid
proxy pairs before network/database access, environment isolation, safe transport
errors, stable remote Secret graphs, legacy snapshot publication, and preserved
Microsoft admission/native behavior. Full Python, Ruff and web build gates remain
required. Mocks and configuration presence are not hosted/provider acceptance.
Post-release acceptance should use existing authenticated identities and bounded
reads, without starting provider jobs, creating connections or running the
private snapshot/lease operators merely to test transport.
