# Code-to-cloud Golden Path demo

## The story

The local demo tenant intentionally contains two code-to-cloud applications, one bounded
Entra discovery boundary, and no generic fixture corpus:

1. **Anna on AWS** — private GitHub source at immutable commit
   `19b38c952c81658d37863e368a7f70f9819ed567`, an independently observed Lambda and ECS
   worker in AWS account `331145994818` / `ap-south-1`, exact Lambda-to-repository proof,
   seven declared tool/action capabilities, six real source/AWS posture findings, three
   fixable vulnerabilities from a partial scan of the exact deployed worker image, and two
   model-specific correlated governance issues.
2. **Summit on Google Cloud** — public GitHub source at immutable commit
   `dacc2bbf9497612d31757ae8dfbdb4697eaa7563`, a private scale-to-zero Cloud Run service in
   project `vertex-api-502308` / `us-central1`, an exact service-to-repository proof, a
   least-privilege runtime service account, and a source-declared Gemini 2.5 Flash model. A
   successful cloud recollection upgrades that declaration to independently observed runtime
   configuration.
3. **Microsoft Entra discovery** — a tenant-wide, read-only application inventory boundary
   for tenant `017c6f31-f951-4bda-a50a-c168c0e6f815`. It currently matches two real
   enterprise applications: **Azure Machine Learning OpenAI** and
   **whitney-openai-secure**. Application inventory, service-principal context, delegated
   grants, application roles, and the tenant's 30-day directory-audit window are complete.
   Sign-in coverage remains partial because the tenant does not have the Entra Premium/B2C
   license required by Microsoft Graph for sign-in logs. Denali retains this limitation as a
   coverage boundary rather than converting it into a reassuring zero.

The dashboard's **Golden Path** panel is the starting point. Each card links to the full
source-to-runtime proof. The most useful demo sequence is:

1. Show the two Golden Path application cards on **Overview**.
2. Open **Code to cloud** and explain the exact immutable-source → declaration → runtime
   chain for Anna, then Summit.
3. Expand Anna's declared tool surface: Slack messages/canvases, HubSpot deal writes, S3
   reads/writes, Lambda invocation, and Microsoft Graph mail. Emphasize that static source
   capability is labelled **not observed**, not presented as executed activity.
4. Open Anna's source/AWS findings, three image vulnerabilities, and two correlated issues.
   Explain that findings are evaluated conditions, vulnerabilities are scanner observations,
   and issues require an exact multi-source evidence join. A `deployed_by` edge remains
   lineage—not a verdict by itself.
5. Open **Sources** or **Connections** to show the exact two-repository, one AWS Region, and
   one GCP project/resource boundaries.
6. Show **Shadow AI**: two catalog-matched Entra enterprise applications are awaiting review.
   Permission counts are observed zeroes under complete grant and app-role coverage; sign-in
   activity is unavailable under the tenant's license and is labelled partial, while the
   30-day directory-audit query completed with no matching changes. The current page name means
   “AI application discovery”; it does not classify either row as unauthorized or prove use.
7. Finish with the evidence boundary: the two source-to-cloud applications, two Entra AI
   application matches, six findings, three vulnerabilities, two correlated issues, one real
   Vertex model invocation, one evidence-linked runtime detection, and no fixture or
   fabricated records.

## Deterministic boundary

[`golden-paths/code-to-cloud.yaml`](../../golden-paths/code-to-cloud.yaml) is the versioned
acceptance contract. It preserves exactly three provider connections, names the two accepted
repositories and three accepted AI workloads, requires both proven deployment edges, permits
the bounded Entra discovery connector, rejects fixture and unrelated connector families, and
caps every high-level row count.

Preview a local reset before changing anything:

```bash
denali-golden-path reset \
  --manifest golden-paths/code-to-cloud.yaml \
  --dsn "$DENALI_DSN"
```

Applying the reset requires the exact tenant UUID twice. It deletes only tenant-scoped Denali
data and disallowed Denali connection records; it never deletes GitHub repositories or cloud
resources:

```bash
denali-golden-path reset \
  --manifest golden-paths/code-to-cloud.yaml \
  --dsn "$DENALI_DSN" \
  --tenant-id 00000000-0000-4000-8000-000000000001 \
  --apply \
  --confirm-tenant 00000000-0000-4000-8000-000000000001
```

After revalidation and collection, enforce the acceptance contract:

```bash
denali-golden-path verify \
  --manifest golden-paths/code-to-cloud.yaml \
  --dsn "$DENALI_DSN"
```

## Collection order

The order matters because source correlation consumes independently observed deployment
targets:

1. Validate the GitHub, AWS, and GCP connections and collect the bounded Entra tenant.
2. Collect AWS and GCP deployments.
3. Collect the `NiSalesAgentStack` topology and posture.
4. Collect GitHub source last; this performs repository inventory, posture, and exact
   code-to-cloud correlation against the already-observed targets.
5. Collect bounded runtime metadata, evaluate issues/detections, then run manifest
   verification.

The GCP connection includes an exact Cloud Asset resource-name selector for Summit. This
keeps the project boundary auditable without importing an older test service that also exists
in the project. Vertex AI `DATA_READ` audit logging is enabled for
`aiplatform.googleapis.com`; a real Summit `GenerateContent` call by its dedicated Cloud Run
service account is retained as bounded runtime evidence. No prompt, response, token, or caller
IP is imported into Denali.

The Entra reader uses only the admin-consented Microsoft Graph application permissions
`Directory.Read.All` and `AuditLog.Read.All`. Local collection uses an ephemeral client secret
that is revoked immediately after each run. The tenant exposes directory audits for a 30-day
window but rejects sign-in-log queries without a Premium/B2C license, so those two planes must
remain independently labelled complete and partial respectively.

The Golden Path SBOM and Grype reports are deliberately partial. They retain only three real,
direct npm component occurrences from the exact Anna ECS image and mark both coverage planes
partial. This creates a short, explainable vulnerability story without claiming the retained
records are a complete image inventory.

## Teardown

The Summit Cloud Run service is private and scales to zero. Its live service currently reports a
maximum scale of 20 instances; reducing that to one remains an explicit operator decision. Its
runtime identity has only `roles/aiplatform.user`. Exact cloud teardown commands and the pinned
image digest remain in the Summit repository. The Golden Path reset itself is local and does not
perform cloud teardown.
