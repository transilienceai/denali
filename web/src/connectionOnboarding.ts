import type { Connection } from "./types";
import type { ConnectionCatalogItem } from "./api";
import { connectionCollectionStatus } from "./connectionCollections.ts";

type ConnectionProvider = Connection["provider"];

export type SharedAwsAvailability = "checking" | "enabled" | "not_enabled" | "error";

export function sharedAwsFailureState(cause: unknown): SharedAwsAvailability {
  // Only an explicit admission 404 means disabled. A 503 can be a broker outage.
  const status = cause instanceof Error && "status" in cause ? cause.status : null;
  return status === 404
    ? "not_enabled"
    : "error";
}

export function showNativeConnectionForm(
  provider: ConnectionProvider,
  showCreate: boolean,
  availability: SharedAwsAvailability,
  nativeRequested: boolean,
): boolean {
  if (!showCreate) return false;
  if (nativeRequested || provider !== "aws") return true;
  return availability === "not_enabled";
}

export function connectionOnboardingPath(
  item: ConnectionCatalogItem | undefined,
  nativeRequested: boolean,
): "shared" | "native" | "unavailable" {
  if (!item) return "unavailable";
  if (nativeRequested && item.native_available) return "native";
  if (item.onboarding_path === "shared" && item.shared_enabled) return "shared";
  if (item.onboarding_path === "native" && item.native_available) return "native";
  return "unavailable";
}

const COVERAGE_NOTES: Record<string, string> = {
  single_region_only: "Reusable AWS access covers one selected Region.",
  additional_aws_planes_require_native: "Additional AWS evidence planes use Denali setup.",
  selected_resource_coverage_requires_native: "Exact Lambda-only coverage currently uses Denali setup.",
  agent_runtime_activity_requires_native: "Foundry agent runtime activity uses Denali setup.",
  shared_activity_window_24_hours: "Activity collection covers up to 24 hours per run.",
  repository_changes_require_explicit_new_selection: "Review and explicitly save repository selection changes.",
  admitted_domain_binding_required: "Choose an approved Workspace domain.",
};

export function connectionCoverageNotes(item: ConnectionCatalogItem): string[] {
  return item.parity_gaps.flatMap((gap) => COVERAGE_NOTES[gap] ? [COVERAGE_NOTES[gap]] : []);
}

export function connectionActionAvailable(connection: Connection, action: "validate" | "collect") {
  if (connection.actions) return connection.actions[action];
  if (connection.lifecycle_state === "disabled") return false;
  if (connection.credential_reference.type.startsWith("platform_shared_") && connection.platform_availability && connection.platform_availability !== "ready") return false;
  return action === "validate" || connection.health_state === "healthy";
}

export type ConnectionJourneyPhase = "grant" | "verify" | "collect";

export function connectionJourney(connection?: Connection, phase: ConnectionJourneyPhase = "grant") {
  const validationRunning = connection?.validation_state === "running";
  const platformUnavailable = connection?.platform_availability !== undefined && !["ready", "not_applicable"].includes(connection.platform_availability);
  const exactValidation = connection?.configuration?.coverage_mode === "selected-resource"
    && connection.last_validation?.credential_state === "passed"
    && connection.last_validation.results.length === 2
    && connection.last_validation.results.every((result) => result.state === "passed")
    && connection.actions?.collect === true;
  const verified = !validationRunning && (connection?.health_state === "healthy" || exactValidation) && !platformUnavailable;
  const hasBoundary = Boolean(connection && (connection.credential_reference.type.startsWith("platform_shared_") || validationRunning || connection.last_validation || verified));
  const collection = connection ? connectionCollectionStatus(connection) : null;
  const state = (complete: boolean, current: boolean) => complete ? "complete" : current ? "current" : "pending";
  return [
    { label: "Grant access", state: connection?.platform_availability && ["disabled", "needs_scope_grant", "requires_shared_setup"].includes(connection.platform_availability) ? "attention" : state(hasBoundary || phase !== "grant", !hasBoundary && phase === "grant") },
    { label: "Verify access", state: platformUnavailable || (connection?.last_validation && !verified && !validationRunning) ? "attention" : state(Boolean(verified), validationRunning || (hasBoundary && !verified) || (!connection && phase === "verify")) },
    { label: "Collect evidence", state: collection?.attention ? "attention" : state(collection?.complete === true, collection?.running === true || (Boolean(verified) && !collection?.complete) || (!connection && phase === "collect")) },
  ];
}
