# Shared Jira metadata reads through Denali

Status: implemented behind `DENALI_ENABLE_SHARED_JIRA_READS=false` by default.
This is a product-owned read adapter to the existing Platform shared Jira broker,
not a Denali Jira connector or a production activation claim. The canonical
named read registry is `src/denali/api/capabilities.py` (additive v1 contract).

## Request path and authorization

The Platform results gateway uses the existing Denali `results:read` receiver:
`GET /internal/v1/capabilities/{operation}`. Denali verifies the exact gateway
machine, purpose, short-lived user and Clerk organization, then checks current
membership and resolves an **existing** Clerk-org → Denali tenant mapping without
creating a tenant. Members and admins may read. No caller chooses an org or tenant.

The fixed Denali handler uses its existing outbound Platform machine identity
and exact organization allowlist. It calls only:

- `GET /internal/v1/connections/jira` for org-scoped inventory;
- `GET /internal/v1/connections/jira/{connection_id}/status` for one selected
  connection and its selected numeric project IDs; and
- `POST /internal/v1/connections/jira/{connection_id}/read` for the broker's
  `projects`, `issues`, or `issue_detail` operation.

The server inserts `clerk_org_id` from verified auth into broker requests.
It never accepts a user-supplied org, tenant, Jira site, upstream URL, JQL,
project array, method, provider token or credential. Only the broker talks to
Jira. Its registered Denali app/machine entitlement, connection ownership,
selected projects and scopes are rechecked by Platform. No broker call is
automatically retried.

## Five additive named reads

| Operation | Gateway query inputs | Bounded response |
| --- | --- | --- |
| `shared-jira-connections` | optional `limit` 1–100 (default 20), `offset` 0–100000 (default 0) | safe org-owned connection page, never credentials |
| `shared-jira-status` | canonical `id` UUID | safe one-connection status and selected project IDs |
| `shared-jira-projects` | canonical `id`, optional `limit` 1–50 (default 20), opaque base64url `cursor` 1–8192 chars | selected project IDs, keys, names and next cursor |
| `shared-jira-issues` | canonical `id`, required decimal `project_id` 1–(2^63−1), optional `limit` 1–50 (default 20), opaque `cursor` | one selected project's safe issue metadata and next cursor |
| `shared-jira-issue-detail` | canonical `id`, required selected `project_id`, required numeric Jira `issue_id` or uppercase Jira key | one issue's safe metadata within the selected project |

The `id` always identifies the Platform connection; it is never a Denali-local
connection UUID. `project_id` must occur in that same connection's broker
status; issue reads pass only that one selected project. The issue selector is
`[1-9][0-9]{0,19}` or
`[A-Z][A-Z0-9_]{0,31}-[1-9][0-9]{0,19}`. Duplicate, unknown,
noncanonical, URL-like, JQL-like or oversized inputs return 422 before the
broker is called. The broker retains its own strict project-filtered read and
opaque cursor verification. Enhanced Jira search may lag; absence is not proof
of deletion.

Denali projects only fixed safe response fields. Connections expose ID, selected
numeric projects, site URL, read scopes, lifecycle/availability and verification
time. Projects expose ID/key/name/type. Issues expose ID/key/project, bounded
summary, status/type/priority names and timestamps. Broker-added fields,
description, comments, attachments, email, cloud IDs, credential references,
tokens, provider errors and raw payloads are discarded. Invalid result identity,
shape, bounds, selected project or cursor fails closed with a generic 502.
Responses are `Cache-Control: no-store`.

## Rollout and verification

`DENALI_ENABLE_SHARED_JIRA_READS` is a public deployment selector copied into
the existing Modal `Secret.from_dict` configuration on every Denali function.
The dev/prod workflows default it to literal `false`; deploy scripts also
default to `false` and reject values other than literal `true` or `false`.
When false, all five reads
return 404. The same value is mounted in local and remote function graphs;
it adds no named Secret or new dependency graph edge. Existing
`DENALI_PLATFORM_CONNECTIONS_ORIGIN`, `DENALI_PLATFORM_MACHINE_SECRET_KEY`
and `DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS` still govern the outbound bridge.
The gateway needs its own independent read discovery/execution gate and a
reviewed adapter pin. Generic CLI/MCP tool discovery can use the five schemas
under existing read consent; no new typed CLI package or OAuth scope is added.

Before enabling in any environment, verify the Denali app/machine entitlement,
exact org admission, Platform broker health, selected Jira site/projects,
approved `jira.projects`/`jira.issues` reads, current user/tenant access and
end-to-end CLI/MCP denial/positive cases. The current Platform production pilot
does not grant Denali a new Jira provider permission by this code change alone.
No production deployment, Jira consent, new OAuth client, copied credential,
customer-cloud write, Jira permission read, setup/disable flow, local Jira
connection, Jira finding, scan, database table or migration is included.
