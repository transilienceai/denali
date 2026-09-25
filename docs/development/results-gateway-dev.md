# Read-only results bridge (development)

Denali keeps its existing browser `/api/v1/*` contract. A separate Transilience
gateway may read selected Denali results through three internal routes on the
Modal API origin:

- `GET /internal/v1/results/summary` — inventory, finding, and issue summaries.
- `GET /internal/v1/results/findings?limit=20&offset=0` — bounded finding rows.
- `GET /internal/v1/results/coverage` — at most 100 latest coverage rows, with
  `total` and `truncated` indicators.

The caller must present a Clerk M2M token minted by the gateway machine and
scoped to the Denali receiver machine. The token must have a `results:read`
purpose and the Clerk `org_id` and `user_id` that the gateway verified from
the user's org-scoped OAuth grant. Denali checks the gateway machine ID, scope,
purpose, and identifiers; it then *looks up* an existing Denali tenant. A
machine request never creates one. No browser session, tenant ID parameter,
provider credential, or database access is accepted on these routes.

Enable only in the isolated `denali-dev` Modal Secret by setting
`DENALI_RESULTS_GATEWAY_MACHINE_ID` and `DENALI_RESULTS_RECEIVER_MACHINE_ID`
(the existing Denali machine ID). The existing
`DENALI_PLATFORM_MACHINE_SECRET_KEY` verifies incoming M2M tokens. With either
machine ID unset, the routes return 404. Production remains disabled. Deploy
through the reviewed `dev` workflow, not from a feature branch.

The gateway, not Denali, must verify Clerk OAuth tokens, require the
`results:read` scope, and confirm the selected user's current organization
membership before minting each downstream token. It must not forward the
user's OAuth token to Denali. Results remain owned by Denali and are never
copied into the shared connections registry.
