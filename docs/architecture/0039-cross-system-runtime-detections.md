# ADR 0039: Cross-system runtime detections require exact joins and explicit authority

## Status

Accepted.

## Context

Provider runtime telemetry, OpenShell enforcement events, inventory, source declarations, effective
policy, approved boundaries, and formal proof output express different kinds of evidence. Combining
them can expose meaningful drift, but only if Denali preserves identity and refuses conclusions when
the required join or authority is missing.

## Decision

Denali adds six deterministic runtime rules:

| Rule | Required evidence | Conclusion |
|---|---|---|
| `DENALI-RUNTIME-OPENSHELL-BOUNDARY-001` | Exact effective and boundary policy digests plus `exceeds_boundary` from the standalone prover | Effective authority exceeds the approved boundary in the retained counterexample domain |
| `DENALI-RUNTIME-OPENSHELL-PROVER-001` | Versioned prover result, required domains, and observed `coverage.domains` | The required boundary conclusion is unsupported, inconclusive, errored, or missing modeled authority |
| `DENALI-RUNTIME-OPENSHELL-CREDENTIAL-001` | Exact declared/effective policy peers and normalized credential-bearing endpoints | Effective composition adds a credentialed destination absent from the direct declaration |
| `DENALI-RUNTIME-DENIAL-PATH-001` | Exact workload-linked OpenShell events | Three denied access attempts followed inside five minutes by success on a changed process or destination path |
| `DENALI-RUNTIME-TELEMETRY-INTEGRITY-001` | Capture attestation/loss signals or one contradictory OCSF record | Runtime telemetry is explicitly interrupted or its action, disposition, status, and outcome disagree |
| `DENALI-RUNTIME-POLICY-MISMATCH-001` | Exact workload, successful destination/process/method metadata, and exact effective policy peer | Observed runtime access is absent from the normalized effective enforcement surface |

Rules do not parse free-form log messages, infer an asset from a runtime name, or treat missing
evidence as a violation. Missing policy peers, destination identity, process identity, required
domains, or workload links increment `incomplete_candidates`. Collection coverage remains
`unknown`, `partial`, `failed`, or `not_supported` as appropriate even when a positive event-backed
detection can be retained.

The access-policy comparison supports exact hosts and OpenShell first-label wildcard hosts, exact
ports, binary globs, and enforced REST method/access presets. A policy shape outside the normalized
summary is incomplete rather than treated as denied. The current rule proves inconsistency with the
effective OpenShell enforcement surface. Source, IAM, and declared-tool conclusions require those
exact control identities to be normalized and joined; the investigation guidance calls for those
systems, but Denali does not claim an IAM or source mismatch from OpenShell evidence alone.

Repeated-denial correlation is scoped to one exact workload. A changed path means a different
`(process, destination, port)` tuple. This sequence is evidence of changed execution behavior, not
proof of malicious intent.

Telemetry interruption comes from the bundle's explicit capture attestation or loss signals. A
partial coverage state alone does not manufacture a detection. Contradiction compares typed fields
within one immutable event.

## Persistence and presentation

The bounded detection snapshot now includes `data_access` and `other` activity categories. Every
detection links to the exact contributing activities and/or policy/workload assets. The six rule
evaluations are hidden in the web application until OpenShell coverage exists or a retained
detection makes the rule relevant to that tenant.

## Consequences

- Boundary failure and lack of prover authority remain different findings.
- A complete `exceeds_boundary` result can create a critical detection; an inconclusive result
  cannot be reinterpreted as either safe or unsafe.
- Runtime/policy drift is deterministic for the supported summary and explicitly incomplete beyond
  it.
- Adding source, IAM, or tool-policy variants later requires new exact inventory/relationship
  evidence and provider-specific acceptance, not broader string matching.
