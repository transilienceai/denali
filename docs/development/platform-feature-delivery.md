# Deliver Denali features to the shared CLI and MCP

Denali owns its business operations and tenant authorization. Browser requests
remain on the existing same-origin API. CLI REST and MCP adapters use the central
Platform gateway and Denali's fixed internal receivers; they do not query Neon.
Use the same existing operation where safe, or a bounded product-owned external
projection when browser responses contain sensitive configuration.

## Agent checklist before a feature PR is finished

1. Identify the owning operation and classify read, write, authenticated handoff
   or intentionally not externally exposed. Operator/credential workflows are not
   automatically public tools. Keep existing APIs and connector compatibility.
2. Update `src/denali/api/capabilities.py` for reads/job starts,
   `src/denali/resource_writes/contract.py` for remediation contracts, and
   `docs/development/capability-surface.json` for public/browser dispositions as
   applicable. Version incompatible names/parameters/semantics; preserve old aliases.
3. Add receiver/handler tests and preserve current Clerk membership, admin checks,
   Clerk-org → Denali tenant UUID mapping, tenant scoping, bounded outputs and
   fail-closed errors. Writes need their exact scope, confirmation, organization
   guard and durable idempotency/job semantics; no automatic provider permission changes.
4. Prepare a paired Platform PR updating the reviewed Denali source pin, fixed
   adapter, MCP schema/annotations and contract checks. Record product and adapter
   PRs and deployment order. Never reimplement Denali business reads in Platform.
5. Decide CLI compatibility: generic tools discover new deployed schemas using
   existing supported scopes; new typed verbs/options, packaged contract changes or
   login scopes require a reviewed CLI release where the client changes. New scopes
   require approved client setup and fresh consent, not shared browser-claim edits.
6. Add a same-PR `docs/platform/changes/<feature>.json` record and update relevant
   examples, tests and the shared public handbook/paired portal snapshot if needed.
7. Run the evidence gate and normal checks; prepare review-only production-main
   PRs. Existing Denali release rules still prohibit unreviewed deployments.

## PR declaration

Use version 1, product `denali`, change `add`, `update` or `no_external_change`,
and meaningful reasons. External add/update declarations list capabilities with
`name`, `kind` (`read`, `write`, `authenticated_handoff`, `not_externally_exposed`)
and `scopes`; their `contract_files`, `documentation_files` and `test_files` must
name distinct real files changed in this PR, within the policy's category-specific
`evidence_paths` allowlists. Delivery records cannot count as evidence. Reviewed
policy changes may extend these allowlists when a canonical location moves.
`cli` contains impact `generic_tools`,
`release_required` or `none` and reason; `gateway` contains `adapter_update` or
`none` and reason. See the canonical
[Platform declaration template](https://github.com/transilienceai/transilience-platform/blob/main/docs/service-delivery.md).

Internal changes use `no_external_change`, empty capability/evidence arrays,
`none` CLI/gateway impacts and a reason explaining preserved external behavior.
These declarations are reviewed evidence, not deployment or exposure authority.

```sh
python3 scripts/check_platform_delivery.py --self-test
python3 scripts/check_platform_delivery.py --base FULL_PR_BASE_COMMIT_SHA
pytest -q tests/test_gateway_capabilities.py tests/test_gateway_product_capabilities.py
ruff check .
```

Use the full immutable PR base SHA. The gate in
`docs/platform/delivery-policy.json` watches Denali/backend, browser-client and
contract changes, and rejects missing/stale declaration evidence. It does not
prove complete semantics or replace Denali's existing surface-parity tests.
Maintainers should require **Platform delivery evidence** after adoption; this
PR does not change repository protection, runtime APIs, scopes or provider roles.

## Ownership and rollout

Product contracts and internal details stay here. Shared onboarding and public
docs live in Platform; `docs/portal/handbook.v1.json` is synchronized to the MCP
portal as a reviewed commit/hash-pinned public snapshot. Never copy secrets or
customer evidence into it. The live authenticated catalog remains the authority
for which operations a user's session can access.

Future work is incremental: finish app-owned feature/receiver parity, update
the paired gateway contract, release client changes only when needed, then
perform approved production acceptance. Browser paths, existing native providers
and unrelated organization data remain unchanged.

See [capability contract](capability-contract.md), [receiver](capability-gateway.md)
and [change/release process](change-and-release-process.md).
