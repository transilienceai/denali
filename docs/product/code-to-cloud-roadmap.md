# Code-to-cloud roadmap

## Goal

Build evidence-led source-to-runtime correlation across AWS, Google Cloud, Azure, and
Kubernetes without treating similar names, tags, or model identifiers as deployment proof.
Every provider slice must retain independent control-plane observation, immutable source
context, exact identity requirements, and visible proven, ambiguous, and unmatched outcomes.

## Sequential delivery plan

1. **Provider-neutral deployment identity layer — complete.** Extract shared provider,
   runtime-kind, scoped identifier, comparison, evidence, and disposition contracts. Adapt
   the existing AWS CDK Lambda/ECS implementation without weakening or changing its accepted
   joins.
2. **Google Cloud Run and Cloud Functions Gen2 — complete.** Bounded independent workload
   inventory, Terraform and deployment-YAML declarations, and exact project/location/resource,
   image, revision, and service-account evidence are implemented. A private, scale-to-zero
   Vertex AI fixture passed the live control-plane correlation acceptance on 2026-08-31; see
   [the acceptance record](gcp-code-to-cloud-live-acceptance-2026-08-31.md).
3. **Azure Container Apps and Azure Functions — complete.** Bounded independent Resource
   Graph inventory, Terraform/Bicep/ARM declarations, and exact subscription/resource-group/
   resource identity with revision, image, and managed-identity context are implemented. A
   private, scale-to-zero Azure OpenAI-capable fixture passed live control-plane, reporting,
   and connected-browser acceptance on 2026-08-31 and was then torn down; see
   [the acceptance record](azure-code-to-cloud-live-acceptance-2026-08-31.md).
4. **Broaden AWS coverage — complete.** Terraform,
   SAM, and CloudFormation declarations now join exact account/Region/name identities to
   independently observed Lambda, ECS task-family, EKS cluster, and SageMaker endpoint
   inventory. Each service has its own validation, inventory, and relationship plane; see
   A live selected-Region role validation and all eight collection planes passed on
   2026-08-31; see [the acceptance record](aws-code-to-cloud-live-acceptance-2026-08-31.md)
   and [the AWS decision record](../architecture/0026-aws-deployment-code-to-cloud.md).
5. **Shared Kubernetes correlation — complete.** EKS, AKS, and GKE workloads share one
   bounded snapshot importer and exact
   provider-cluster, namespace, kind, name, service-account, UID/revision, and image-digest
   evidence contract. GKE and AKS cluster resources are independently observed alongside the
   existing EKS inventory. A zero-compute EKS fixture passed live exact-match, unmatched,
   ambiguity, persistence, served-API, evidence-minimization, and teardown acceptance on
   2026-08-31; see
   [the acceptance record](kubernetes-code-to-cloud-live-acceptance-2026-08-31.md) and
   [the Kubernetes decision record](../architecture/0027-shared-kubernetes-code-to-cloud.md).

## Demo operationalization — complete

The accepted provider slices now feed a deliberately small
[two-application Golden Path](golden-path-demo.md): Anna on AWS and Summit on GCP. A
versioned manifest defines exact connection, repository, workload, relationship, forbidden
connector, and row-budget boundaries. The guarded reset command removes stale localhost
evidence without touching cloud resources; the verification command fails closed if the
rebuilt tenant drifts from the story. The Overview page exposes both applications before the
presenter enters the detailed code-to-cloud evidence view.

## Hosted read-only demo access — planned

After the Clerk-protected deployment at `denali.transilience.cloud` is operational, add a
**View the demo** path for visitors who are not ready to create an account. The public path
must open a read-only, resettable Golden Path snapshot rather than bypass authentication into
an operator tenant. It must expose no connection credentials, onboarding actions, mutation
controls, or customer evidence; the UI must visibly identify the workspace as a demo. Build
this as a separate authorization mode and tenant boundary, then add browser acceptance for
direct links, Back/Forward navigation, session transitions, and attempted mutations.

## Acceptance rules for every step

- A runtime target is eligible only when independently and actively observed.
- Provider and runtime kind must agree before identifiers are evaluated.
- All required scoped identifiers must match using their declared exact or prefix semantics.
- Ambiguous or unmatched candidates remain observable and never create a deployment edge.
- Artifact identity and source-revision attestation remain separate claims.
- Provider test deployments must be minimal, tagged for Denali validation, cost-bounded, and
  accompanied by an explicit teardown path.
