# Denali handoff: Golden Path, runtime evidence, Entra discovery, and hosted merge

Date: 2026-09-01 America/Los_Angeles (cloud evidence continued into 2026-09-02 UTC)

This checkpoint is the starting document for the next session. Read, in order:

1. [`AGENTS.md`](../../AGENTS.md)
2. [Codebase and system map](../architecture/codebase-and-system-map.md)
3. [Hosted multi-tenant ADR](../architecture/0028-hosted-multi-tenant-runtime.md)
4. [Golden Path presenter/operator guide](../product/golden-path-demo.md)
5. [Hosted pilot checklist](../deployment/pilot-launch-checklist.md)

## Executive state

The local Golden Path is now a compact, evidence-backed demonstration rather than a generic demo
seed. It contains Anna on AWS, Summit on GCP, two real Entra AI application matches, real Vertex
runtime metadata, deterministic findings/vulnerabilities/issues/detections, and no fixture activity.

The functional work and the colleague's hosted Vercel/Clerk/Modal/Neon work were reconciled without
force-pushing. At the start of this handoff commit, both GitHub remotes point to merge commit
`47f001ab02d01e9c27c130f9ca27610598e5d39a`:

- `origin`: `https://github.com/transilienceai/denali.git`
- `personal`: `https://github.com/kkmookhey/denali.git`

The documentation changes in this checkpoint follow that functional baseline. Check `git log -1`
for the final handoff commit.

## Repository and local runtime

- Branch: `main`
- Local web: `http://127.0.0.1:3080`
- Local API: `http://127.0.0.1:8088`
- Local PostgreSQL: `127.0.0.1:55450`
- Local tenant: `00000000-0000-4000-8000-000000000001`
- Compose services were healthy at handoff: `web`, `api`, and `postgres`.
- Do **not** run `denali-demo-seed`; it would pollute the bounded Golden Path tenant.

User-owned untracked paths were intentionally excluded from every commit:

- `971CC4D9-F32C-4434-81EF-822845DCD4F1.mov`
- `output/`

The `.mov` was the product walkthrough reviewed earlier in the session. `output/` belongs to a
different website artifact. Preserve both.

## Local Golden Path acceptance state

`golden-paths/code-to-cloud.yaml` is named
`anna-aws-summit-gcp-and-entra-discovery`. Verification passed with:

| Evidence class | Count |
| --- | ---: |
| Assets | 38 |
| Findings | 6 open medium |
| Vulnerabilities | 3 open high, all with fixes |
| Issues | 2 open high |
| Runtime activity | 1 successful model invocation |
| Runtime detections | 1 open medium |
| Collection runs | 38 |
| Fixture activity | 0 |

Inventory kinds at handoff:

```text
ai_agent=3
ai_application=2
ai_datastore=2
ai_model=4
ai_tool=7
ai_workload=3
application_endpoint=2
cloud_resource=5
code_repository=2
identity=5
software_component=3
```

Every retained asset currently has governance status `unreviewed`. That is useful for the demo but
should eventually be curated into a smaller number of explicit approve/reject decisions.

## Golden Path story

### Anna on AWS

- Repository: `github.com/kkmookhey/anna-the-sales-agent`
- Immutable revision: `19b38c952c81658d37863e368a7f70f9819ed567`
- AWS account: `331145994818`
- Selected Region: `ap-south-1`
- Observed workloads:
  - `arn:aws:lambda:ap-south-1:331145994818:function:ni-sales-agent`
  - `arn:aws:ecs:ap-south-1:331145994818:task-definition/NiSalesAgentStackProposalWorkerTaskC2F0F9A1:20`
- Seven source-declared capabilities: invoke Lambda, read/write the configured S3 proposal
  artifact, send Microsoft 365 mail, write a HubSpot deal, post a Slack message, and write a Slack
  canvas.
- These capability cards are explicitly **not observed** execution.
- Six real source/AWS posture findings.
- Three high vulnerabilities with scanner-provided fixes from a partial scan of the exact deployed
  ECS worker image.
- Two high evidence-linked governance issues tied to exact Bedrock model identifiers.

The local connection is `fd48da13-ed53-43d9-b832-af7cdae48aa4`, display name
`Sara Sales AWS Code-to-Cloud Acceptance`, and is healthy. The selected local operator profile used
earlier was `sara-sales`; `shasta-scanner` was authorized for disposable AWS fixtures but is not
required for the current Golden Path.

### Summit on Google Cloud

- Repository: `github.com/kkmookhey/denali-gemini-demo`
- Immutable revision: `dacc2bbf9497612d31757ae8dfbdb4697eaa7563`
- Project: `vertex-api-502308`
- Region: `us-central1`
- Cloud Run service: `denali-gemini-demo`
- Resource name:
  `//run.googleapis.com/projects/vertex-api-502308/locations/us-central1/services/denali-gemini-demo`
- Execution identity:
  `denali-gemini-demo@vertex-api-502308.iam.gserviceaccount.com`
- Model: `gemini-2.5-flash`
- Live service URL exists but the service is private:
  `https://denali-gemini-demo-o35ufognaq-uc.a.run.app`
- Scale-to-zero is enabled. Live Cloud Run `maxScale` is currently **20**, not one. Decide whether
  to reduce it; this handoff did not mutate the service.

Project IAM now has exactly one audit configuration added by this session:

```yaml
service: aiplatform.googleapis.com
auditLogConfigs:
  - logType: DATA_READ
```

A harmless real request generated Cloud Audit Log event `1xxak0ae1xm6k` at
`2026-09-02T03:16:37.788691Z`:

- method: `google.cloud.aiplatform.v1.PredictionService.GenerateContent`
- permission: `aiplatform.endpoints.predict`
- actor: Summit's dedicated service account
- resource: `projects/vertex-api-502308/locations/us-central1/publishers/google/models/gemini-2.5-flash`
- outcome: success

Denali retained method, actor, model/resource, outcome, timestamp, locator, and record digest. It
did not retain prompt, response, access token, or caller IP. The event created one medium
`DENALI-RUNTIME-UNREVIEWED-MODEL-001` detection because the exact invoked model is still
`unreviewed`.

The local GCP connection is `5aec018a-9bc9-46f3-9b3d-b8895f855e6e`, display name `Summit GCP`,
and is healthy. There is also a native runtime activity coverage record using connection key
`gcp:vertex-api-502308` from the post-policy import.

### Microsoft Entra AI application discovery

Azure CLI account at handoff:

- user: `kkmookhey@yahoo.com`
- tenant: `017c6f31-f951-4bda-a50a-c168c0e6f815`
- subscription: `8cd2b4cc-c789-466d-a8f7-8f51fb20985d` (`Azure CIS Agent Testing`)

A dedicated single-tenant application was created:

- display name: `Denali Shadow AI Reader`
- application/client ID: `badb4bfc-7aa8-4d5e-9c9d-fff282ca7102`
- application object ID: `e7491136-738f-425b-ba72-227632b0cdd6`
- service principal object ID: `8d130797-d2cc-4acf-a80c-2258cba9e0e1`
- audience: `AzureADMyOrg`

The user explicitly approved and the app has exactly these Microsoft Graph application roles:

- `Directory.Read.All` — app role ID `7ab1d382-f21e-4acd-a863-ba3e13f7da61`
- `AuditLog.Read.All` — app role ID `b0afded3-3588-46d8-8b3d-9842eff778da`

Admin consent persists until revoked. **No password credential currently exists.** Several
short-lived secrets were created only in process memory for collection and immediately revoked.
`az ad app credential list` returned `[]` at handoff. Therefore local Entra data is a current
snapshot, not a continuously refreshable connection.

The bounded collector examined 328 enterprise service principals and matched two applications:

1. `Azure Machine Learning OpenAI`
   - catalog: OpenAI / ChatGPT
   - category: Assistant
   - verified publisher: Microsoft Corporation
   - zero delegated grants and zero application roles under complete permission coverage
2. `whitney-openai-secure`
   - catalog: OpenAI / ChatGPT
   - category: Assistant
   - publisher not provided
   - zero delegated grants and zero application roles under complete permission coverage

Latest effective coverage:

- application inventory: complete
- service-principal context: complete
- delegated grants: complete
- application roles: complete
- directory audits: complete for the tenant's available 30-day window; zero matching changes
- sign-ins: partial; Microsoft Graph returned
  `Authentication_RequestFromNonPremiumTenantOrB2CTenant`

The first 90-day directory-audit run is retained historically as failed because Microsoft reported
that the minimum allowed date was 2026-08-02. The later 30-day run completed. Coverage consumers
must choose the latest run per connector/connection/plane rather than treating historical failures
as current.

Terminology decision: these two rows are catalog matches awaiting review. They are not proven
unauthorized and there is no observed sign-in use. Rename the product surface from **Shadow AI** to
**AI application discovery**; reserve “Shadow AI” for observed use that violates explicit policy.
Consider also renaming the Entra app registration to `Denali AI Application Discovery Reader`.

## Code delivered in functional baseline `47f001a`

- Repository source extraction now retains exact source declarations for models, deployments, and
  seven Anna tools/actions.
- GCP deployment collection attaches source-declared Vertex model context to exact Cloud Run
  workloads without presenting declarations as observed execution.
- Code-to-cloud UI renders repository -> workload -> execution identity -> model plus declared
  action surface.
- Tool/action typography was increased and the responsive grid remains bounded.
- Activity normalization links exact Vertex model resources and exact service-account identities.
- Added the deterministic unreviewed-model runtime detection.
- Added model-specific issue rules and evidence linking.
- Golden Path documentation, manifest, budgets, and tests now include Summit runtime and bounded
  Entra discovery.
- The empty Shadow AI state is N/A when no Entra evidence boundary exists; with Entra evidence it
  displays the two real applications and honest coverage states.
- The hosted multi-tenant work from the organization remote was merged with the Golden Path commit
  without force-pushing or losing either history.

## Hosted pilot state inherited from the organization remote

The repository now contains a deployed invitation-only pilot architecture:

```text
Web:  https://denali.transilience.cloud
API:  https://transilience-denali-prod--denali-production-api.modal.run
DB:   Neon database denali; migrations 001 through 012 applied
Auth: Clerk Organizations, currently development keys
```

According to the committed pilot checklist, authenticated sign-in, Organization switching, all
protected pages, deep-link refresh, same-origin API proxying, Modal API, durable validation worker,
and Neon migrations have smoke acceptance. This session merged and read that work but did **not**
repeat the hosted browser or production acceptance.

Hosted provider variables are still absent. GitHub should be configured first, then AWS, then GCP
and Azure. Hosted provider collection is not durable even though validation is; collection still
uses API-container background tasks and must migrate to PostgreSQL jobs plus Modal workers.

## Verification completed

Final handoff verification after installing the newly merged hosted extras:

- Python: `223 passed, 23 skipped`
- Web: `10 passed`
- TypeScript/Vite production build: passed
- Ruff: passed
- `git diff --check`: passed
- Internal Markdown link check: passed
- Golden Path manifest verification: passed with the counts above
- Local Compose web/API/PostgreSQL health: passed

The production build emits a non-failing chunk warning: the main JavaScript bundle is roughly
527 KB minified. `npm audit` reports three high-severity package nodes representing one transitive
build-time advisory chain:

```text
@vercel/config -> @vercel/routing-utils -> path-to-regexp
GHSA-9wv6-86v2-598j: backtracking regular-expression denial of service
```

`@vercel/config` is a development/build dependency. npm's proposed fix is a breaking downgrade to
`@vercel/config@0.0.32`; do not run `npm audit fix --force` without testing the Vercel routing
contract. Track dependency remediation and route-level bundle splitting as follow-up work.

Both GitHub remotes accepted the reconciled history. The screen recording and `output/` remained
untracked.

## Browser acceptance

The user manually inspected the updated local product and said the result looked good. The current
session's in-app browser-control service was unavailable (`Invalid browser service environment`),
so the assistant could not take a final automated browser screenshot. Do not substitute Playwright
for this product-specific browser acceptance; use the configured browser-control capability when
available or ask the user to inspect.

## Important security and teardown boundaries

No provider secret, OAuth token, client secret, database DSN, Clerk secret, private key, prompt, or
response was committed or written into this handoff.

### Revoke the Entra discovery integration

The cleanest teardown is to delete the dedicated application registration after confirming the
target IDs above. If preserving the app, remove only the two Microsoft Graph app-role assignments
from service principal `8d130797-d2cc-4acf-a80c-2258cba9e0e1`. Resolve current assignment IDs
again before deletion; do not rely blindly on copied IDs.

Read-only checks:

```bash
az ad app credential list --id badb4bfc-7aa8-4d5e-9c9d-fff282ca7102 -o json
az rest --method GET \
  --url 'https://graph.microsoft.com/v1.0/servicePrincipals/8d130797-d2cc-4acf-a80c-2258cba9e0e1/appRoleAssignments'
```

### Revert Vertex Data Access logging

Do not apply the stale pre-change IAM policy or etag. Export the **current** project policy, remove
only the `aiplatform.googleapis.com` `DATA_READ` audit configuration, review the binding diff, and
apply the edited current policy. Retain the audit setting if real Vertex runtime demonstrations are
still wanted.

### Tear down Summit

Use the exact teardown commands in `kkmookhey/denali-gemini-demo`. Confirm the Cloud Run service,
runtime service account, builder identity, artifact image, and any added IAM bindings before
deletion. The Golden Path reset deletes only local Denali tenant data; it never deletes cloud
resources.

## Known gaps and next decisions

Recommended order for the next session:

1. Rename **Shadow AI** to **AI application discovery** across navigation, headings, product docs,
   tests, and optionally the Entra app registration. Preserve the existing “catalog match means
   review” evidence boundary.
2. Decide whether public “View the demo” should be a read-only Golden Path tenant/snapshot behind a
   deliberate Clerk-free route. Do not bypass authentication into a mutable production tenant.
3. Populate `denali.transilience.cloud` with a reproducible read-only Golden Path snapshot or build
   an explicit tenant-scoped import/export path. Do not run the generic demo seed.
4. Configure hosted GitHub and AWS and complete create -> setup/callback -> validate -> collect ->
   disable -> delete acceptance. Then add GCP and Azure.
5. Move all hosted collection work to durable PostgreSQL jobs and Modal workers.
6. Move Clerk from development to production keys, verify invitation-only access, `org:member`
   mutation denial, and cross-Organization isolation with non-empty data.
7. Split the Neon runtime and migration roles, enable alerts/backups, and perform a restore drill.
8. Decide whether Summit `maxScale` should be reduced from 20 to 1 for cost/risk containment.
9. Decide whether to retain or revoke project-wide Vertex `DATA_READ` logging after the demo.
10. Resolve the Vercel build-time `path-to-regexp` advisory and split the main frontend bundle.

## Exact continuation commands

```bash
cd /Users/kkmookhey/Projects/denali
git status --short
git log -5 --oneline --decorate --graph
docker compose ps
```

If the editable console scripts are stale after `pyproject.toml` changes, reinstall the worktree.
This workspace's virtual environment is uv-managed and does not include `pip`:

```bash
UV_CACHE_DIR=/private/tmp/denali-uv-cache \
  uv pip install --python .venv/bin/python -e '.[api,aws,azure,gcp,github,hosted,dev]'
```

Run the standard gates before the next push:

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
npm --prefix web ci
npm --prefix web test -- --run
npm --prefix web run build
```

Verify the local Golden Path without mutating it:

```bash
DENALI_DSN='postgresql://denali:denali-local@127.0.0.1:55450/denali' \
  .venv/bin/python -c 'from denali.golden_path import main; main()' \
  verify \
  --manifest golden-paths/code-to-cloud.yaml \
  --tenant-id 00000000-0000-4000-8000-000000000001
```

The handoff is complete only when these documentation changes are committed and both `origin/main`
and `personal/main` point to the same final commit.
