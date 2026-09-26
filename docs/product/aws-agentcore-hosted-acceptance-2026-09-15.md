# AWS AgentCore hosted acceptance — 2026-09-15

This record covers the production hosted acceptance of the metadata-only AWS AgentCore runtime
plane. It contains identifiers and bounded outcomes only. It intentionally excludes AWS request
and response bodies, session contents, credentials, external IDs, tokens, and source artifacts.

## Environment and revision

- Provider: AWS AgentCore
- Date and UTC window: 2026-09-15 21:16–21:27 UTC
- Operator: KK Mookhey / Codex
- Production Modal revision: `a2b471828ffa822997fb2f2a6e690a4e548d224b`
- Production deployment workflow: <https://github.com/transilienceai/denali/actions/runs/34874947970>
- Production Vercel revision observed through GitHub deployment status:
  `94432e67f97f2e40b57ccba3254fe331627eae8e`
- Denali tenant UUID: `3cf9aef8-17fe-4d57-a878-c0af70adf1db`
- Connection UUID: `149bef8c-d96c-44f2-82f6-6ae296bdfbb5`
- AWS account and Region: `331145994818`, `ap-south-1`
- AgentCore runtime ID: `DenaliP0Acceptance-hvx65Q8J4y`
- Applicable ADR: [ADR 0035](../architecture/0035-aws-agentcore-runtime-detection-and-response.md)

## Preconditions

- [x] Same-origin `/api/healthz` returned `200` with `status=ready`.
- [x] An unauthenticated `/api/v1/context` request returned `401`.
- [x] No validation or collection job was active for the new connection.
- [x] The Denali connection declared only AgentCore inventory and metadata-only runtime activity in
      one selected Region.
- [x] The temporary customer grant was bounded to exact external IDs and read-only AgentCore and
      CloudWatch Logs calls. No access key was created or stored.

## Hosted result

- [x] Created an isolated production Denali AWS connection plan.
- [x] Created AgentCore Runtime version 1 from a minimal direct-code artifact and observed
      `READY`.
- [x] Invoked version 1 successfully with a bounded acceptance response.
- [x] Updated the same runtime to version 2 with ADOT instrumentation and observed `READY`.
- [x] Invoked version 2 successfully and produced one provider-native metadata span.
- [x] Denali validation passed all five selected checks: runtime inventory, gateway inventory,
      workload-identity inventory, memory inventory, and runtime-span activity.
- [x] The durable primary collection completed with one Region complete and no partial or failed
      Regions.
- [x] The durable runtime worker retained one new span with one Region complete and no partial or
      failed Regions.
- [x] The production UI showed the `DenaliP0Acceptance` session, a successful
      `aws.agentcore.InvokeAgentRuntime` event, one exact agent correlation, and zero detections.
- [x] The session investigation preserved ordered trace/span identifiers and reported
      `content_policy=metadata_only`.
- [x] The exported evidence package used schema-versioned metadata-only fields. Recursive key
      inspection found no prompt, response, request/response payload, tool argument/result,
      authorization, access-token, secret, or token field.
- [x] Disabled the disposable connection after operator confirmation. The hosted UI displayed
      `Disabled`, removed validation and collection actions, and retained the completed inventory
      and metadata-only runtime summaries.
- [x] Re-opened Runtime activity after disable and confirmed that the `DenaliP0Acceptance` session
      and successful AgentCore invocation remained visible.
- [ ] Delete-retention acceptance is intentionally deferred. On 2026-09-16 the operator chose to
      keep this disabled connection as an acceptance fixture; no delete confirmation was submitted.
- [ ] The fixture's external-ID trust grant, live runtime, execution role, and versioned S3 bucket
      remain. Either govern them as a reusable fixture or remove them after a different disposable
      AWS connection proves the required delete-retention contract.

## Coverage boundary

The accepted activity was an AgentCore Runtime invocation. Fresh Lambda/OpenTelemetry spans from
the same AWS account were separately observed in `aws/spans`, but they lacked an AgentCore anchor
and Denali correctly excluded them from this plane. The accepted record contained one agent
invocation, no model or tool calls, and made no detection or safety claim.

## Result

- Runtime create/update/invoke: passed
- Denali validation: passed
- Durable inventory collection: passed
- Durable AgentCore activity collection: passed
- Hosted investigation and export: passed
- Metadata-only privacy inspection: passed
- Lifecycle disable: passed
- Delete and post-delete retention proof: deferred by operator decision; a different disposable
  connection is required to close this lifecycle step
- Multi-Organization authorization: tracked by the separate P0 isolation gate
