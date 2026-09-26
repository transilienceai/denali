# Shasta Google Workspace pilot bridge

Status: PR #64 deployed the fixed-name three-Secret mount and the four operator
bindings are present. A first invocation delivered a signed snapshot to Shasta, but
the snapshot correctly reports `failed`: zero facts, no observed capabilities, and
all four Workspace reads unavailable. The provider authorization stage remains to be
diagnosed; a bridge receipt is not collection acceptance. PR #58's first deployment
stopped during image build because a private dependency was inaccessible to Modal's
builder; PR #61 removed that dependency. PRs #62–#64 corrected the Secret mounts.

Denali remains the credential owner. The fixed `collect_shasta_pilot_workspace` function
runs in the existing `denali-production` Modal app, whose identity is intended to
match the Google Workload Identity Federation condition. It uses a small in-repository,
reviewable Shasta v1 snapshot adapter and no private-repository build credential.
It loads the active Workspace connection through
Denali's tenant-and-connection-scoped repository call, mints short-lived delegated
read-only credentials, and publishes only a bounded Shasta snapshot. No provider
token or raw Google response is logged, returned, or copied into a tenant record.

## Operator configuration

The following four values are configured in the existing `shasta-denali-bridge` Secret in the `denali-prod` Modal
environment, without placing values in the shared GitHub provider Secret, repository,
GitHub Actions output, PR, or shell history:

- `DENALI_SHASTA_WORKSPACE_TENANT_ID`: verified Denali tenant UUID owning the
  `iisecurity.in` connection;
- `DENALI_SHASTA_WORKSPACE_CONNECTION_ID`: exact active Workspace connection UUID;
- `DENALI_SHASTA_WORKSPACE_SOURCE_ID`: corresponding Shasta Google Workspace source UUID;
- `DENALI_SHASTA_WORKSPACE_BRIDGE_SECRET`: unique random per-source HMAC secret of at
  least 32 bytes, matching Shasta's private source-bridge registry.

The bridge destination and provider are fixed in code to
`https://shasta.transilience.cloud/pilot` and `google_workspace`. No HTTP caller can
select a different tenant, connection, source, provider, or URL. The secret must be
rotated on both sides together. Use the protected Denali production deployment
workflow for the exact merged `main` SHA; never `modal run` this function from a
feature branch, because that creates a temporary app identity rejected by the
Google workload-identity condition.

Only the Shasta Workspace function mounts the fixed-name `shasta-denali-bridge`
Secret, alongside the existing core and provider Secrets; all other functions retain
just the first two. Modal evaluates module-level dependencies in the deploy process
and remote worker, so the mount list cannot depend on a deploy-shell-only variable.
The `denali-dev` environment has its own Secret of that name containing only a disabled
marker, not the production binding; the bridge is not configured or accepted there.

If the first snapshot is failed, an authorized operator may invoke the deployed
`diagnose_shasta_pilot_workspace` function by Modal lookup. It performs only bounded,
read-only Google probes and returns the failing stage, an allowlisted error code or
HTTP status; it never returns provider payloads, access tokens, or raw exceptions.
Do not run a feature-branch `modal run` for diagnosis because that changes the Modal
workload identity. Recheck the source snapshot after correcting the verified provider
configuration; a successful bridge receipt alone is insufficient.

Once deployed and configured, an authorized operator may invoke the **already
deployed** function via `python scripts/invoke_shasta_workspace_bridge.py`. This
script prints only source/snapshot identifiers, replay state, and a digest. A first
successful receipt proves delivery, not collection completeness or a control
decision. Inspect Shasta's source status, four required capabilities, fact count,
pagination, expected domain, and audit-package provenance. Exercise permission
denial, stale snapshot, replay, and cross-tenant rejection before calling the source
fully connected. This is an operator-triggered first-customer pilot, not a recurring
or durable collection scheduler; that remains a separate production workflow.

Rollback: disable the Shasta source bridge binding and restore the previous
Denali production commit through the protected deployment workflow. Do not revoke
or alter the customer's Google domain-wide delegation merely to roll back Shasta;
Denali's existing Google Workspace use remains independent.
