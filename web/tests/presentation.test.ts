import assert from "node:assert/strict";
import test from "node:test";
import {
  applicableDetectionEvaluations,
  inventoryEvidenceSummary,
} from "../src/presentation.ts";
import type {
  Coverage,
  RuntimeDetection,
  RuntimeDetectionEvaluation,
} from "../src/types.ts";

const entraEvaluation: RuntimeDetectionEvaluation = {
  rule_uid: "DENALI-RUNTIME-ENTRA-CONSENT-001",
  state: "unknown",
  confirmed_detections: 0,
  incomplete_candidates: 0,
  detail: null,
  evaluated_at: "2026-08-31T00:00:00Z",
};

const awsEvaluation: RuntimeDetectionEvaluation = {
  ...entraEvaluation,
  rule_uid: "DENALI-RUNTIME-AWS-RISKY-SEQUENCE-001",
};

test("Entra rules are hidden when the tenant has no Entra evidence boundary", () => {
  assert.deepEqual(applicableDetectionEvaluations([entraEvaluation], [], []), []);
});

test("Entra rules remain visible when Entra coverage or a retained detection exists", () => {
  const coverage = [{ connector_id: "denali.entra_ai" }] as Coverage[];
  assert.deepEqual(applicableDetectionEvaluations([entraEvaluation], [], coverage), [entraEvaluation]);

  const detections = [{ rule_uid: entraEvaluation.rule_uid }] as RuntimeDetection[];
  assert.deepEqual(applicableDetectionEvaluations([entraEvaluation], detections, []), [entraEvaluation]);
});

test("AWS AgentCore rules require runtime coverage or a retained detection", () => {
  assert.deepEqual(applicableDetectionEvaluations([awsEvaluation], [], []), []);

  const coverage = [{ plane: "aws_agent_runtime_activity" }] as Coverage[];
  assert.deepEqual(applicableDetectionEvaluations([awsEvaluation], [], coverage), [awsEvaluation]);

  const detections = [{ rule_uid: awsEvaluation.rule_uid }] as RuntimeDetection[];
  assert.deepEqual(applicableDetectionEvaluations([awsEvaluation], detections, []), [awsEvaluation]);
});

test("inventory evidence wording does not present source declarations as verified runtime", () => {
  const declared = inventoryEvidenceSummary("declared", 1);
  assert.match(declared.headline, /declared by source evidence/);
  assert.match(declared.detail, /does not establish deployment, runtime use/);
  assert.doesNotMatch(declared.headline, /externally verified/);

  const verified = inventoryEvidenceSummary("externally_verified", 2);
  assert.match(verified.headline, /externally verified/);
  assert.match(verified.headline, /2 parts/);
});
