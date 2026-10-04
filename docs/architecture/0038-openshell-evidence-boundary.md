# ADR 0038: OpenShell evidence ingestion is explicit, metadata-only, and loss-aware

## Status

Accepted.

## Context

NVIDIA OpenShell emits native OCSF JSONL from sandbox supervisors and gateways, exposes authored
and fully composed effective policies as separate views, and provides a standalone policy prover.
Those sources answer different questions:

- OCSF records show observed enforcement, configuration, and lifecycle events.
- an authored policy shows direct operator or agent intent;
- an effective policy includes provider-composed access and is the policy relevant to runtime;
- a boundary policy states the approved maximum;
- a prover result states whether one candidate is contained by one boundary for its explicitly
  listed modeled domains.

OpenShell's watch stream and file sinks can lose events. Schema downgrade also removes fields.
Absence from an unbounded JSONL fragment therefore cannot establish that an event did not occur.
Likewise, only `within_boundary` is a passing prover result; `unsupported`, `inconclusive`, and
missing required domains must remain visible.

## Decision

Denali imports a bounded directory whose `manifest.json` uses schema version 1 and names exactly
five artifacts:

```json
{
  "schema_version": 1,
  "gateway_uid": "gateway-prod-1",
  "sandbox_uid": "sandbox-123",
  "sandbox_name": "review-agent",
  "policy_revision": "v7",
  "capture": {
    "source": "sandbox_jsonl",
    "started_at": "2026-10-04T10:00:00Z",
    "ended_at": "2026-10-04T11:00:00Z",
    "complete": true,
    "loss_signals": []
  },
  "required_prover_domains": [
    "filesystem", "network_l4", "network_rest", "process", "landlock"
  ],
  "artifacts": {
    "ocsf": "events.jsonl",
    "declared_policy": "declared-policy.yaml",
    "effective_policy": "effective-policy.yaml",
    "boundary_policy": "boundary-policy.yaml",
    "prover": "prover.json"
  }
}
```

The bundle is imported with `denali-openshell-import <directory>`. Artifact paths cannot be
absolute or escape the directory. Every file and record is bounded before parsing. Policy YAML
rejects duplicate keys and must declare `version: 1`. The prover artifact must be the versioned
JSON output of `openshell-prover check ... --output json`; its named candidate and boundary must
match the bundle artifact names.

`metadata.uid` is the immutable OCSF event identity. `container.uid`, not the event UID, is the
OpenShell sandbox identity. Denali creates one exact workload key from the manifest gateway and
sandbox IDs and links events to it only when the identities agree. A bundle spanning multiple
sandboxes is rejected.

The declared, effective, and boundary policies are distinct guardrail assertions with independent
file digests and locators. Denali retains an allowlisted structural summary—destination host and
port, protocol, enforcement, credentialed boolean, method names, binary selectors, MCP tool
names, filesystem entry counts, and process identity—but not whole policy documents, middleware
configuration, credential values, request bodies, or arbitrary user maps. The prover result is a
fourth assertion containing its versioned verdict, required and observed domains, stable reason
code, safe counterexample fields, and both policy digests.

OCSF activity retains only identifiers and enforcement metadata. URL paths and query strings,
headers, bodies, command arguments, environment values, and arbitrary `unmapped` fields are not
persisted. OCSF Detection Finding records continue through the findings boundary and never create
inventory.

Coverage is independent by plane. OCSF planes are complete only when the manifest attests a
complete bounded interval, reports no loss signal, every record has `metadata.uid` and
`container.uid`, and the export is native OCSF 1.8. A downgraded schema or any loss signal makes
every OCSF plane partial. Prover coverage is complete only for a conclusive supported result whose
`coverage.domains` contains every manifest-required domain. Unsupported is `not_supported`;
inconclusive, error, or missing domains are partial. A complete coverage state does not mean the
policy passed: `exceeds_boundary` is complete evidence of a failed containment check.

## Consequences

- Runtime enforcement, authored intent, effective authority, approved boundary, and proof
  authority remain separately attributable.
- Later cross-system detections can distinguish an observed violation from incomplete telemetry
  or an unsupported proof domain.
- File ingestion is a local evidence path in this slice. A hosted OpenShell connection, durable
  shipper, or gateway callback would require the standard authenticated, tenant-scoped durable-job
  design before it can be added.
- `capture.complete` is an exporter/operator attestation checked for contradictions, not a claim
  Denali can derive from an arbitrary JSONL fragment.
