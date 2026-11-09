import type { Connection } from "./types";
import { connectionCollectionStatus } from "./connectionCollections.ts";
import { githubSourceCollectionProgress } from "./githubSourceCollectionProgress.ts";

export type ConnectionProgressStepState = "complete" | "current" | "pending" | "attention";

export type ConnectionProgress = {
  phase: "preparing" | "validating" | "collecting";
  eyebrow: string;
  title: string;
  detail: string;
  steps: Array<{
    label: string;
    state: ConnectionProgressStepState;
  }>;
};

const PROVIDER_LABELS: Record<Connection["provider"], string> = {
  aws: "AWS",
  azure: "Azure",
  azure_repos: "Azure Repos",
  entra: "Microsoft Entra",
  gcp: "Google Cloud",
  github: "GitHub",
  google_workspace: "Google Workspace",
};

function busyAction(connection: Connection, busy: string | null) {
  const suffix = `:${connection.id}`;
  return busy?.endsWith(suffix) ? busy.slice(0, -suffix.length) : null;
}

export function getConnectionProgress(connection: Connection, busy: string | null): ConnectionProgress | null {
  const provider = PROVIDER_LABELS[connection.provider];
  const action = busyAction(connection, busy);
  const collecting = connectionCollectionStatus(connection).running || action?.startsWith("collect") === true;
  const validating = connection.validation_state === "running"
    || action === "validate"
    || action === "complete"
    || (connection.provider === "aws" && action === "launch");
  const preparing = action === "launch" && connection.provider !== "aws";
  const verifyingAwsRole = connection.provider === "aws"
    && connection.credential_reference.type === "aws_assume_role"
    && validating;

  if (validating) {
    if (verifyingAwsRole) {
      return {
        phase: "validating",
        eyebrow: "AWS SETUP IN PROGRESS",
        title: "Verifying the AWS role and declared access",
        detail: "This run has not yet established access to this connection's IAM role. A CloudFormation launch normally retries every 10 seconds for up to 15 minutes while AWS creates the role; manual validation checks current access without waiting for stack creation. Previous results remain historical until this run finishes. You can safely leave and return. If AWS reports a rollback, review the stack Events.",
        steps: [
          { label: "Check IAM role access", state: "current" },
          { label: "Validate access", state: "pending" },
          { label: "Collect evidence", state: "pending" },
        ],
      };
    }
    return {
      phase: "validating",
      eyebrow: "VALIDATION IN PROGRESS",
      title: `${provider} access is being validated`,
      detail: "Denali is checking the declared read-only access in the background. This page refreshes automatically, and it is safe to leave and return. Healthy validation automatically continues to first evidence collection.",
      steps: [
        { label: "Access setup", state: "complete" },
        { label: "Validate access", state: "current" },
        { label: "Collect evidence", state: "pending" },
      ],
    };
  }

  if (collecting) {
    const validationState: ConnectionProgressStepState = connection.health_state === "healthy" ? "complete" : "attention";
    const sourceProgress = githubSourceCollectionProgress(connection);
    return {
      phase: "collecting",
      eyebrow: "EVIDENCE COLLECTION IN PROGRESS",
      title: sourceProgress?.title ?? `${provider} evidence is being collected`,
      detail: sourceProgress ? `${sourceProgress.summary}. ${sourceProgress.detail}` : "Denali is reading the declared evidence planes in the background. This page refreshes automatically, and it is safe to leave and return.",
      steps: [
        { label: "Access setup", state: "complete" },
        { label: "Validate access", state: validationState },
        { label: "Collect evidence", state: "current" },
      ],
    };
  }

  if (preparing) {
    return {
      phase: "preparing",
      eyebrow: "PREPARING SECURE SETUP",
      title: `${provider} setup is being prepared`,
      detail: "Denali is creating the short-lived, reviewable setup instructions for this connection.",
      steps: [
        { label: "Access setup", state: "current" },
        { label: "Validate access", state: "pending" },
        { label: "Collect evidence", state: "pending" },
      ],
    };
  }

  return null;
}
