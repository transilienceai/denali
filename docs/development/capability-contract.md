# Denali capability contract v1

Denali owns the read operation names, parameter allowlist, and mapping to its
existing API handlers in `src/denali/api/capabilities.py`. The browser still
uses its same-origin `/api/v1/*` client. The shared Platform REST/CLI/MCP
adapters call Denali's authenticated internal receiver; they do not query
Denali's database or implement its business reads.

`CAPABILITY_CONTRACT_VERSION` is the compatibility boundary. When changing an
operation name, parameter, or response meaning, introduce a new version and
update the pinned Platform adapter in a separate reviewed PR. Keep old names
as aliases during migration; do not silently repurpose one. Platform's CI
checks its pinned read registry against this product-owned source revision.

The three current write operations remain separately gated by `denali:write`,
organization-admin RBAC, and idempotency. This contract does not authorize
customer AWS or GitHub remediation.
