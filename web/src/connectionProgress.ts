import type { Connection } from "./types";

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
  entra: "Microsoft Entra",
  gcp: "Google Cloud",
  github: "GitHub",
  google_workspace: "Google Workspace",
};

function collectionState(connection: Connection) {
  if (connection.provider === "github") return connection.source_collection_state;
  if (connection.provider === "entra" || connection.provider === "google_workspace") {
    return connection.evidence_collection_state;
  }
  return connection.deployment_collection_state;
}

function busyAction(connection: Connection, busy: string | null) {
  const suffix = `:${connection.id}`;
  return busy?.endsWith(suffix) ? busy.slice(0, -suffix.length) : null;
}

export function getConnectionProgress(connection: Connection, busy: string | null): ConnectionProgress | null {
  const provider = PROVIDER_LABELS[connection.provider];
  const action = busyAction(connection, busy);
  const collecting = collectionState(connection) === "running" || action?.startsWith("collect") === true;
  const validating = connection.validation_state === "running"
    || action === "validate"
    || action === "complete"
    || (connection.provider === "aws" && action === "launch");
  const preparing = action === "launch" && connection.provider !== "aws";

  if (validating) {
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
    return {
      phase: "collecting",
      eyebrow: "EVIDENCE COLLECTION IN PROGRESS",
      title: `${provider} evidence is being collected`,
      detail: "Denali is reading the declared evidence planes in the background. This page refreshes automatically, and it is safe to leave and return.",
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
