import type {
  Coverage,
  RuntimeDetection,
  RuntimeDetectionEvaluation,
} from "./types";

const ENTRA_RULE_UIDS = new Set([
  "DENALI-RUNTIME-ENTRA-CONSENT-001",
  "DENALI-RUNTIME-ENTRA-FAILURES-001",
]);
const AWS_AGENT_RUNTIME_RULE_UIDS = new Set([
  "DENALI-RUNTIME-AWS-UNDECLARED-MODEL-001",
  "DENALI-RUNTIME-AWS-UNAPPROVED-TOOL-001",
  "DENALI-RUNTIME-AWS-RISKY-SEQUENCE-001",
]);

export function applicableDetectionEvaluations(
  evaluations: RuntimeDetectionEvaluation[],
  detections: RuntimeDetection[],
  coverage: Coverage[],
): RuntimeDetectionEvaluation[] {
  const hasEntraEvidence = coverage.some((item) => item.connector_id === "denali.entra_ai");
  const hasAwsAgentRuntimeEvidence = coverage.some(
    (item) => item.plane === "aws_agent_runtime_activity",
  );
  const observedRules = new Set(detections.map((item) => item.rule_uid));
  return evaluations.filter(
    (item) =>
      ((!ENTRA_RULE_UIDS.has(item.rule_uid) || hasEntraEvidence) &&
        (!AWS_AGENT_RUNTIME_RULE_UIDS.has(item.rule_uid) || hasAwsAgentRuntimeEvidence)) ||
      observedRules.has(item.rule_uid),
  );
}

export function inventoryEvidenceSummary(
  assertionType: string,
  relationshipCount: number,
): { headline: string; detail: string } {
  const linked = `linked to ${relationshipCount} part${relationshipCount === 1 ? "" : "s"} of the AI system`;
  if (assertionType === "externally_verified") {
    return {
      headline: `This resource is externally verified and ${linked}.`,
      detail: "Security conclusions remain separate from this inventory assertion.",
    };
  }
  if (assertionType === "observed") {
    return {
      headline: `This resource was directly observed and is ${linked}.`,
      detail: "Observation does not by itself establish approval or safety.",
    };
  }
  if (assertionType === "declared") {
    return {
      headline: `This resource is declared by source evidence and ${linked}.`,
      detail: "Source evidence does not establish deployment, runtime use, approval, or safety.",
    };
  }
  return {
    headline: `This resource is inferred from retained evidence and ${linked}.`,
    detail: "Review the evidence before treating this inference as deployed or active.",
  };
}
