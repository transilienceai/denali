# Clerk-backed shared connection discovery

This is prepared, opt-in source. No Clerk metadata, credential, provider grant,
production environment or native Denali connection is changed by this PR.

## Lookup boundary

When `DENALI_CONNECTION_SETTINGS_SOURCE=clerk`, the existing server-only shared
connection client obtains shared listing items directly from Clerk Organization
private metadata at `transilience_connections`. The provider-grouped version-1
projection is published by Platform. Denali returns only its sanitized application
view; the private `settings` dictionary, external IDs, other application views and
unrelated private metadata never reach the browser, CLI or MCP results. Existing
allowlisted identifier fields remain unchanged: an exact-resource AWS view may
already contain its role/resource ARN. This change does not add those private
settings to a view that did not previously expose them.

`src/denali/integrations/clerk_connection_settings.py` is an exact vendored copy
of Platform's internal `src/transilience_platform/clerk_connection_settings.py`,
not an independent connection schema. Review and synchronize these files together
in the paired change; do not introduce a separately evolving product reader.

The following existing GET lookups change their backing service, not their wire
contract: `/v1/connections`, `/internal/v1/connections/jira`,
`/internal/v1/connections/google-workspace` and
`/internal/v1/connections/azure-repos`. The existing `/v1/connections` composition
remains AWS/GitHub/GCP/Azure/Entra/Azure Repos. Provider config, setup, status,
validation, lifecycle actions, credential leases and provider reads remain on the
Platform broker. A settings snapshot does not grant cloud access or establish
that validation/collection succeeded. Native Denali records and durable jobs stay
in Denali's database.

Current authentication, live membership/RBAC, server-resolved organization,
Clerk-org-to-tenant mapping and `DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS` remain
required. The existing Platform origin and machine credential are still needed
for broker operations; a Clerk settings key does not activate a dark bridge.

## Configuration and compatibility

- `DENALI_CONNECTION_SETTINGS_SOURCE=platform` is the compatible default and
  rollback selection. Unknown source values fail configuration validation.
- `DENALI_CONNECTION_SETTINGS_SOURCE=clerk` requires explicit
  `DENALI_CONNECTION_SETTINGS_ENVIRONMENT=production|development` and the
  server-only `CLERK_CONNECTION_SETTINGS_SECRET_KEY`. Its Clerk key type and,
  when present, Modal environment must match the selected environment.
- The backend key remains in Modal Secrets. It is not a machine token and must
  not be put in Vercel, `VITE_*`, a browser, local CLI configuration, session claims
  or metadata itself. This implementation does not create or broaden that key.
- Version, organization, environment, stable IDs, application ownership, field
  allowlists, response bounds and a maximum five-minute snapshot lifetime are
  validated. Missing, expired, malformed or wrong-org metadata returns a redacted
  unavailable response. Clerk mode never retries through the old Platform listing
  API or serves a stale cache. A valid empty projection remains empty.

CLI/MCP still use the existing authenticated Denali receiver through the shared
gateway. Public operations, scopes and sanitized response schemas are unchanged;
there is no new discovery permission, token export or CLI package requirement.

## Review and activation

The paired Platform change owns publication and refresh of the private projection
under the same version-1 contract, defined in its `docs/clerk-connection-settings.md`.
No activation follows merely from merging the code. Separately review the exact
environment/org/provider publisher allowlist and backend credential, publish and
compare fresh snapshots for **every currently allowed shared-connection
organization**, then select Clerk mode for the approved Denali instance. The
source switch is instance-wide, not a per-organization canary switch. Do not
narrow the existing organization allowlist to activate this lookup, because that
would also change broker access for other organizations.
Exercise organization switching, expired/missing metadata, an empty snapshot,
per-app scope visibility and removal/disable propagation. Confirm cloud broker
revocation and native jobs still work independently. Roll back only the source
selection if needed; do not delete registry rows, provider grants or unrelated
Clerk metadata.

Verification in this branch is offline/synthetic. Hosted UI/CLI/MCP acceptance,
the actual publisher schedule and production metadata freshness are separate
release checks, not claimed by unit tests.
