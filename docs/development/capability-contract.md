# Denali capability contract v1

Denali owns the read operation names, parameter allowlist, and mapping to its
existing API handlers in `src/denali/api/capabilities.py`. The browser still
uses its same-origin `/api/v1/*` client. The shared Platform REST/CLI/MCP
adapters call Denali's authenticated internal receiver; they do not query
Denali's database or implement its business reads.

The two connection reads use dedicated bounded repository projections rather
than the existing browser connection responses. The latter include full
configuration and validation details and are not suitable for external tools.

`CAPABILITY_CONTRACT_VERSION` is the compatibility boundary. When changing an
operation name, parameter, or response meaning, introduce a new version and
update the pinned Platform adapter in a separate reviewed PR. Keep old names
as aliases during migration; do not silently repurpose one. Platform's CI
checks its pinned read registry against this product-owned source revision.

Governance, response proposal/review, typed connection job starts, and durable vulnerability-import submission
remain separately gated by `denali:write`, organization-admin RBAC, and idempotency.
Import submission additionally requires `expected_org_id` and explicit JSON
`confirmed=true`; the complete request is bounded at 2 MiB. Additive context and
metadata-only runtime export reads reuse the existing handlers; gateway runtime
exports are bounded at 100 activities and 2 MiB, preserving `session.truncated`.
The exhaustive operation dispositions and sensitive workflow exceptions are
recorded in [capability-surface.json](capability-surface.json). This contract does
not authorize customer AWS or GitHub remediation.
