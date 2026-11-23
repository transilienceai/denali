# Platform broker Modal authentication

Denali's shared-connection client sends the existing Clerk machine bearer and
an additional Modal proxy token to the reviewed development or production
Platform broker. The proxy token controls transport access; organization
allowlists, tenant mapping, current broker entitlements and provider leases
remain authoritative. Native Denali cloud authentication is unchanged.

The same dedicated pair also protects the existing claims-bound resource-write
lease transport. Its exact receiver, purpose, grant, request digest and reviewer
checks remain unchanged, and this release does not enable remediation actions.

The environment-local Modal Secret `denali-platform-modal-proxy` contains only
`DENALI_PLATFORM_MODAL_PROXY_KEY` and `DENALI_PLATFORM_MODAL_PROXY_SECRET`.
Use a separate token for Denali in each environment. Both fields are required,
must have the Modal `wk-`/`ws-` prefixes, and are never included in Clerk requests,
connection settings, API responses or logs. Missing/invalid pairs fail closed.

The existing shared-origin deployment selection mounts this Secret on the same
runtime function graph as the existing broker identity. A disabled shared
bridge does not require the Secret. Remote module re-import uses the replayed
runtime origin to preserve that graph. The private development probe also
declares this dependency; it is not an acceptance step for this change because
it requests a provider lease and performs a provider read.

Provision the dedicated Secret before deploying a broker-enabled environment.
Deploy and verify the reviewed change in development, then use the normal
protected production workflow from merged main. Preserve every provider flag,
organization allowlist and native Clerk settings enrollment. Verify that direct
anonymous broker requests fail, authorized inventory reads still work, and
cross-organization requests remain denied. Do not queue validation or collection
as transport acceptance. Never recover by disabling Modal authentication.

This is internal transport plumbing. Product receiver contracts, public tools,
CLI scopes and sanitized response shapes do not change. Platform and the MCP
gateway have paired transport changes; customer clients never receive the
server-held Modal credentials.

Provider callback metadata accepts the exact same-environment gateway
(`https://mcp-dev.transilience.cloud` or `https://mcp.transilience.cloud`) with
the original fixed callback path. The fixed legacy broker origin is retained
for a coordinated rollout, while cross-environment or arbitrary hosts remain
rejected. Product final-return URLs and their one-time state checks are unchanged.
