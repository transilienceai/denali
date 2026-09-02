# Denali

Denali is an independent, open-source AI security platform for evidence-backed inventory,
posture, attack paths, and runtime context. It keeps observed facts, inferred relationships,
security conclusions, and coverage limits separate so an evaluator can see both what Denali
knows and what it could not verify.

The repository contains a runnable local product: a PostgreSQL-backed API, a standalone web
application, deterministic issue and detection engines, provider onboarding, first-party
collectors, and bounded importers. It is not an extension of a CSPM. Prowler is supported as
an external findings source through OCSF.

## Current status

Status terms in this README are deliberately independent:

- **Shipped** means the capability is implemented on `main` and covered by repository tests
  and/or a production web or container build.
- **Locally accepted** means the customer-like workflow was also completed against live
  provider resources from a local Denali deployment.
- **Pending live acceptance** means the implementation and local verification exist, but the
  documented human, browser, or provider end-to-end pass is incomplete.
- **Planned** means the capability is not implemented in this repository.

| Capability | Implementation | Acceptance evidence |
| --- | --- | --- |
| Evidence store, API, web UI, connectors, importers, issues, and runtime detections | **Shipped** | Locally verified by the automated and PostgreSQL suites and the production web build |
| Self-service AWS connection | **Shipped** | **Locally accepted** against a live AWS account, including Quick Create, exact account binding, enabled-Region discovery, and independent plane validation |
| Self-service Microsoft Azure connection | **Shipped** | **Pending live acceptance**. Live subscription setup and healthy validation succeeded after RBAC propagation, but the final connected-browser, unselected-subscription, partial-state, disable, and delete pass remains open |
| Self-service Google Cloud connection | **Shipped** | **Locally accepted** against three live projects, with a unique keyless principal and all declared project/plane validations passing |
| Self-service GitHub connection | **Shipped** | **Locally accepted** through the organization-owned GitHub App against 18 exact repositories, with all 54 repository/plane validations passing |
| GCP and Azure code-to-cloud correlation | **Shipped** | **Locally accepted** against independently observed, private scale-to-zero fixtures with exact source identity, PostgreSQL reporting, and browser evidence |
| AWS Lambda, ECS, EKS, and SageMaker code-to-cloud correlation | **Shipped** | **Locally accepted** against exact live account/Region validation and eight independent deployment collection planes |
| Shared EKS, GKE, and AKS workload correlation | **Shipped** | **Locally accepted** through a live, control-plane-only EKS fixture with exact workload UID/revision, service-account, image-digest, negative-case, persistence, API, and teardown evidence; GKE and AKS workload identities remain covered by automated contract tests |
| GitHub source-to-cloud correlation | **Shipped** | **Locally accepted** against two immutable GitHub revisions, with all source/inventory/posture/correlation planes complete and two independently observed runtime links proven |
| Two-application code-to-cloud Golden Path | **Shipped** | Anna on AWS and Summit on GCP are bounded by a versioned reset/verify manifest with exact source-to-runtime links, declared model/tool/action context, real Vertex activity, Entra discovery context, three image vulnerabilities, two correlated governance issues, and a dedicated dashboard story |

These connection statuses describe onboarding and access validation. They do **not** mean
that provider collection ran or that inventory, findings, or a security verdict exist.

## What is implemented

Denali presents the following product surfaces in the web application and API:

- AI inventory and evidence-backed relationships for agents, applications, models, MCP
  servers and tools, guardrails, frameworks, pipelines, data stores, workloads,
  repositories, identities, and software components.
- Atomic configuration and imported findings, scanner-neutral vulnerabilities, and
  deterministic issues assembled only from sufficient independent evidence.
- GitHub-backed, immutable-revision source collection and code-to-cloud views that require
  exact deployment identifiers, preserve unmatched and ambiguous candidates, and keep
  artifact identity separate from unattested source revision claims.
- Provider-neutral runtime activity plus deterministic, evidence-linked runtime detections.
- Source coverage that keeps complete, partial, failed, unsupported, and unknown states
  visible.
- Stable application routes with direct deep links and browser Back/Forward navigation.
- A manifest-bounded Golden Path dashboard for a small, reproducible two-application demo;
  see the [operator and presenter guide](docs/product/golden-path-demo.md).
- Connection lifecycle and access validation for AWS, Azure, Google Cloud, and GitHub,
  including explicit scope selection and disable-before-delete safeguards.

Implemented collection and import paths include:

| Source | Current path |
| --- | --- |
| Source repositories | Local or GitHub App-backed static Python, TypeScript, JavaScript, Terraform, SAM/CloudFormation YAML and JSON, Cloud Run YAML, Kubernetes YAML, ARM JSON, and Bicep analysis; bounded repository posture; exact-identifier code-to-cloud correlation |
| MCP Streamable HTTP | Initialization and paginated `tools/list` observation without tool invocation |
| AWS | Bedrock Agents Classic, AgentCore, bounded Lambda/ECS/EKS/SageMaker deployment inventory, CloudFormation-stack inventory and posture, and Bedrock management activity from CloudTrail Event History |
| Google Cloud | Cloud Run, Cloud Run functions Gen2, and GKE cluster inventory through Cloud Asset RESOURCE snapshots; Vertex AI audit activity from Cloud Logging |
| Microsoft Azure | Container Apps, Function Apps, and AKS cluster inventory through Azure Resource Graph with exact Azure code-to-cloud identity; Entra activity remains a separate connector |
| Microsoft Entra | AI application, permission, sign-in, and application-management collection through a separate Microsoft Graph connector |
| External findings and scanners | OCSF findings, Syft SBOMs, and Grype vulnerability reports |
| Runtime exports | AWS Bedrock CloudTrail, Google Cloud Vertex AI, Google Workspace Gemini, and Microsoft Entra AI sign-in JSON |

Provider validation and collection remain separate boundaries. A healthy connection does not
claim that collection ran. GitHub validation reads no source blobs; an explicit collection
action separately resolves each selected repository to an immutable revision, applies hard
tree/file/byte limits, analyzes a temporary snapshot, and discards its token and source files.

## Evidence boundaries

Denali's implementation follows a few non-negotiable rules:

- Connection health proves only that declared, read-only entrypoints were callable for the
  recorded identity and scope at a recorded time.
- Collection coverage is separate from connection health. A failed or partial collection
  cannot withdraw previously observed inventory or resolve findings by absence.
- Findings and runtime events do not manufacture inventory assets or graph edges. Identity
  and correlation require exact, independently observed identifiers.
- Inventory is not a finding; a finding is not an issue; activity is not a detection; and
  none of these is automatically a risk verdict or confirmed incident.
- Unsupported, unselected, unavailable, and unknown scope remains visible rather than
  becoming an empty or safe result.
- Current collectors retain bounded metadata and evidence. Customer cloud credentials and
  transient provider access tokens are not written to evidence or connection records; raw
  one-time setup capabilities are not retained after use. Raw prompts or responses, secret
  values, and arbitrary scanner payloads are also excluded.
- Demo records are visibly identified as fixture evidence.

The canonical model is richer than OCSF because it must preserve durable asset identity and
relationships. OCSF remains an interchange boundary for findings and activity, not a source
of invented Denali graph identity.

## Evaluate Denali locally

Docker is the shortest path to the product:

```bash
docker compose up -d --build
docker compose exec api denali-demo-seed
```

Open the web application at <http://127.0.0.1:3080>. The API is at
<http://127.0.0.1:8088>, with interactive documentation at
<http://127.0.0.1:8088/docs>. PostgreSQL is exposed on `127.0.0.1:55450`.

The seed command creates clearly labelled fixture inventory, findings, vulnerabilities,
issues, runtime activity, and detections so the evaluator can inspect the evidence and
coverage UX without provider credentials. A useful first pass is:

1. Review **Inventory** and open a resource's assertions and relationships.
2. Compare **Findings**, **Vulnerabilities**, and **Issues** to see atomic facts kept separate
   from composed attack paths.
3. Compare **Runtime activity** with **Runtime detections**.
4. Review **Sources** for explicit coverage state.
5. Open **Connections** to inspect the four shipped onboarding flows. Actions that depend on
   an external operator identity or artifact publisher remain unavailable until configured.

The local Compose runtime uses one configured tenant and has no end-user authentication or
authorization layer. It is an evaluation and development stack, not a production deployment
recipe. Data persists in the `denali-postgres` Docker volume.

For the Clerk Organizations, Vercel, Modal, and Neon pilot deployment, start with the
[ordered launch checklist](docs/deployment/pilot-launch-checklist.md), then use the
[hosted multi-tenant pilot runbook](docs/deployment/hosted-pilot.md). Hosted mode maps each
active Clerk organization to a stable Denali tenant UUID, enforces admin-only mutations, and
runs provider validation through durable Modal jobs. The canonical service boundaries, secret
ownership, tenant isolation rules, and durable-work standard are recorded in
[ADR 0028](docs/architecture/0028-hosted-multi-tenant-runtime.md).

## Run collectors and importers

For CLI work, install the provider extras you need and point the commands at the local
database:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[api,aws,azure,gcp,github,dev]'
export DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali
```

The installed entrypoints include `denali-repo-scan`, `denali-mcp-observe`,
`denali-agentcore-scan`, `denali-aws-scan`, `denali-aws-stack-scan`,
`denali-aws-stack-posture`, `denali-repository-posture`, `denali-code-to-cloud`,
`denali-kubernetes-import`, `denali-ocsf-import`, `denali-syft-import`, `denali-grype-import`,
`denali-activity-import`, `denali-aws-runtime`, `denali-gcp-vertex-runtime`,
`denali-gcp-deployments-scan`, and
`denali-entra-scan`. Use each command's `--help` output for its exact scope and inputs.

## Provider onboarding

Self-service onboarding requires operator-owned integration identities and, for AWS, Azure,
and GCP setup artifacts, a private short-lived publisher. The customer grants only the
documented read scope and retains control of provider-side IAM or App installation state.
Denali does not accept customer access keys, service-account JSON keys, personal access
tokens, or cloud CLI sessions.

The accepted contracts, operational requirements, validation planes, lifecycle behavior,
and evidence limits are documented here:

- [ADR 0018 — AWS role onboarding](docs/architecture/0018-self-service-aws-connections.md)
- [ADR 0019 — Azure multi-tenant application and selected subscriptions](docs/architecture/0019-self-service-azure-connections.md)
- [ADR 0020 — GCP keyless principal and selected projects](docs/architecture/0020-self-service-gcp-connections.md)
- [ADR 0021 — GitHub App and exact repository boundaries](docs/architecture/0021-self-service-github-connections.md)
- [ADR 0022 — GitHub immutable source collection](docs/architecture/0022-github-source-collection.md)
- [GitHub App registration and operator configuration](docs/deployment/github-app.md)

The latest acceptance records are the
[AWS](docs/handoffs/2026-08-29-self-service-aws-checkpoint.md),
[Azure](docs/handoffs/2026-08-29-self-service-azure-checkpoint.md),
[GCP](docs/handoffs/2026-08-29-self-service-gcp-checkpoint.md), and
[GitHub](docs/handoffs/2026-08-30-self-service-github-checkpoint.md) checkpoints.

## Architecture guide

Start with the product and evidence boundaries, then follow only the slice being evaluated:

- [Codebase and system map](docs/architecture/codebase-and-system-map.md) for the repository
  layout, end-to-end data flow, local and hosted topology, persistence, frontend, connectors,
  evaluation engines, security boundaries, tests, and safe change recipes
- [Standalone product](docs/architecture/0001-standalone-product.md) and
  [OCSF boundary](docs/architecture/0002-ocsf-boundary.md)
- [Hosted multi-tenant runtime](docs/architecture/0028-hosted-multi-tenant-runtime.md) for the
  Vercel, Clerk, Modal, and Neon deployment, tenant authorization, secrets, and durable jobs
- [Evidence-bearing issues](docs/architecture/0005-evidence-bearing-issues.md)
- [SBOM-first vulnerability model](docs/architecture/0006-sbom-first-vulnerability-model.md),
  [artifact correlation](docs/architecture/0013-artifact-vulnerability-correlation.md), and
  [package occurrence identity](docs/architecture/0014-package-occurrence-identity.md)
- [Evidence-led code to cloud](docs/architecture/0010-evidence-led-code-to-cloud.md),
  [provider-neutral deployment identity](docs/architecture/0023-provider-neutral-deployment-identity.md),
  [GCP code to cloud](docs/architecture/0024-gcp-code-to-cloud.md),
  [Azure code to cloud](docs/architecture/0025-azure-code-to-cloud.md),
  [AWS deployment code to cloud](docs/architecture/0026-aws-deployment-code-to-cloud.md),
  [shared Kubernetes code to cloud](docs/architecture/0027-shared-kubernetes-code-to-cloud.md),
  [static artifact inclusion](docs/architecture/0011-static-artifact-inclusion.md), and
  [deployment artifact provenance](docs/architecture/0012-deployment-artifact-provenance.md)
- [Provider-neutral runtime activity](docs/architecture/0015-provider-neutral-runtime-activity.md),
  [Entra shadow AI and runtime](docs/architecture/0016-entra-shadow-ai-and-runtime.md), and
  [runtime detections](docs/architecture/0017-evidence-led-runtime-detections.md)

Product-preview definitions remain available for
[inventory](docs/product/inventory-preview.md),
[configuration findings](docs/product/configuration-findings-preview.md), and
[issues](docs/product/issues-preview.md).

## Pending acceptance, planned work, and current limits

Pending acceptance is not the same as planned implementation:

- Azure needs the remaining human browser, unselected-scope, partial-state, disable, and
  delete acceptance checks.

Documented planned or deferred capabilities are not shipped:

- GitHub branch-protection and pull-request posture through a separate, explicitly granted
  Administration-read plane.
- Live acceptance of GitHub source collection and correlation against selected repositories
  and independently observed cloud workloads.
- GitHub installation/repository lifecycle reconciliation and GitHub Enterprise Server.
- Slack and Jira onboarding after GitHub acceptance.
- Application-wide typography and clearer elapsed-time context during bounded cloud-IAM
  propagation waits.
- Automatic collector scheduling after a connection validates; hosted connections still
  validate access only and existing collectors remain operator-run.

Prompt- and response-content telemetry is neither shipped nor silently planned into the
current cloud roles. It remains an explicit product-policy decision that would require
separate tenant opt-in, permissions, redaction, retention, encryption, and evidence
semantics.

## Development checks

```bash
pytest
ruff check .
npm --prefix web ci
npm --prefix web run build
```

The default test run skips PostgreSQL integration tests unless `DENALI_TEST_DSN` is set. Run
that contract gate explicitly against the local Compose database:

```bash
DENALI_TEST_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  pytest -q tests/test_inventory_postgres.py
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
