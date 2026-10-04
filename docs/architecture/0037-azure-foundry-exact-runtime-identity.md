# ADR 0037: Azure Foundry runtime identity comes from independent configuration inventory

Status: Accepted

## Context

The metadata-only Foundry trace collector records provider-native project, agent, model-deployment,
and tool identifiers. Until now those identifiers remained unresolved unless another connector had
already established an asset with the same natural key. Runtime activity cannot create inventory:
doing so would turn an execution claim into independent configuration evidence.

Microsoft Foundry exposes agent configuration through the project data plane. The built-in Foundry
User role includes broad write-capable data actions and is not an appropriate collection grant.
Microsoft separately defines the read data action
`Microsoft.CognitiveServices/accounts/AIServices/agents/read`.

## Decision

1. Add the explicit `azure.agent_runtime_inventory` connection scope. It is separate from
   `azure.agent_runtime_activity`; selecting runtime telemetry does not silently expand Denali's
   cloud permission.
2. The Azure setup script creates an idempotent custom role containing only the Foundry agent read
   data action and assigns it at each discovered Foundry project in the selected subscriptions.
   Subscription Reader remains the control-plane grant used for project discovery.
3. Collection discovers projects through Azure Resource Graph, then lists agent configuration from
   the exact project endpoint using an `https://ai.azure.com/.default` token. Requests are restricted
   to HTTPS hosts ending in `.services.ai.azure.com` and paths below `/api/projects/`.
4. The collector retains only project ID, agent ID/name/version/kind, model deployment name, and
   tool name/type. It does not retain instructions, descriptions, environment variables, tool
   schemas, credentials, endpoints, or arbitrary provider metadata.
5. Natural keys exactly match the runtime normalizer:
   - project: lower-cased Azure resource ID;
   - agent: `<project-id>/agents/<agent-id-lower>`;
   - model deployment: `<project-id>/model-deployments/<deployment-name-casefold>`;
   - tool: `<agent-key>/tools/<tool-name-casefold>`.
6. Agent-to-project `hosted_on` and agent-to-model/tool `uses` relationships are observed
   configuration evidence. Missing, malformed, truncated, or failed project reads produce explicit
   partial or failed coverage and never withdraw previously observed inventory.
7. Runtime events that arrive before inventory keep their exact provider keys. Migration 021 and
   the inventory transaction resolve those references only after same-tenant authoritative
   inventory exists.

## Consequences

- Azure Foundry agent, model-deployment, and declared-tool activity can join deterministically to
  independent inventory regardless of collection order.
- The data-plane role is narrower than Foundry User and cannot create, update, delete, or invoke an
  agent.
- A project created after onboarding will appear in discovery but collection will be partial until
  the read-only role is assigned at that new project. Re-running Azure setup is the supported
  idempotent repair path.
- Foundry definitions that do not expose a model or stable tool name remain unresolved. Denali does
  not substitute display-name or fuzzy matching.
