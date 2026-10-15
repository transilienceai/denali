import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type SharedAwsConnection, type SharedAwsValidation } from "./api";
import { sharedAwsFailureState, type SharedAwsAvailability } from "./connectionOnboarding";
import { platformConnectionId, type SharedConnectionAdapterProps } from "./sharedConnectionAdapter";
import { useSharedStatusPolling } from "./useSharedStatusPolling";
import { INITIAL_AWS_ACCESS, SHARED_AWS_SCOPES, sharedAwsConfiguration, type AwsAccessSelection } from "./sharedAwsOnboarding";

function AwsAccessFields({ value, onChange, allowedScopes, automatic, exact = false, locked = false }: {
  value: AwsAccessSelection; onChange: (value: AwsAccessSelection) => void; allowedScopes: string[]; automatic: boolean; exact?: boolean; locked?: boolean;
}) {
  return <fieldset className="connection-access-selection" disabled={locked}>
    <legend>Regions and read-only evidence</legend>
    <label>Region coverage<select value={value.coverageMode} onChange={(event) => onChange({ ...value, coverageMode: event.target.value as AwsAccessSelection["coverageMode"] })}><option value="selected">Selected Regions</option>{automatic && <option value="automatic">All enabled Regions</option>}{exact && <option value="selected-resource">One exact Zip Lambda and execution role</option>}</select></label>
    {value.coverageMode !== "selected-resource" && <label>Deployment Region<input required value={value.deploymentRegion} onChange={(event) => onChange({ ...value, deploymentRegion: event.target.value })} /></label>}
    {value.coverageMode === "selected" && <label>Regions (up to 40, separated by commas)<input required value={value.regionText} onChange={(event) => onChange({ ...value, regionText: event.target.value })} /></label>}
    {value.coverageMode === "selected-resource" ? <>
      <p>Read configuration and IAM policy evidence for one pinned Zip Lambda only. No account discovery, source download, invocation, or account-wide health claim. Platform creates a separate read-only role.</p>
      {(["function_arn", "execution_role_arn", "expected_model_id"] as const).map((field) => <label key={field}>{field === "function_arn" ? "Exact Lambda ARN (without alias or version)" : field === "execution_role_arn" ? "Lambda execution role ARN" : "Expected Bedrock model ID or ARN"}<input required maxLength={300} value={value.selectedResource?.[field] ?? ""} onChange={(event) => onChange({ ...value, selectedResource: { kind: "lambda_zip", function_arn: "", execution_role_arn: "", expected_model_id: "", ...value.selectedResource, [field]: event.target.value } })} /></label>)}
    </> : SHARED_AWS_SCOPES.filter((scope) => allowedScopes.includes(scope.id)).map((scope) => <label key={scope.id}><input type="checkbox" checked={value.scopes.includes(scope.id)} onChange={(event) => onChange({ ...value, scopes: event.target.checked ? [...value.scopes, scope.id] : value.scopes.filter((id) => id !== scope.id) })} />{scope.label}</label>)}
  </fieldset>;
}

export function SharedAwsPilot({ canWrite, onChanged, onAvailabilityChange, connection, onAttached, onProgress, supportedCoverageModes = ["selected", "automatic"] }: SharedConnectionAdapterProps & { onAvailabilityChange?: (availability: SharedAwsAvailability) => void; supportedCoverageModes?: string[] }) {
  const [availability, setAvailability] = useState<SharedAwsAvailability>("checking");
  const [loadError, setLoadError] = useState("");
  const [items, setItems] = useState<SharedAwsConnection[]>([]);
  const [selectedId, setSelectedId] = useState(() => platformConnectionId(connection));
  const [accountId, setAccountId] = useState("");
  const [partition, setPartition] = useState<"aws" | "aws-us-gov" | "aws-cn">("aws");
  const [creationAccess, setCreationAccess] = useState<AwsAccessSelection>(INITIAL_AWS_ACCESS);
  const [attachmentAccess, setAttachmentAccess] = useState<AwsAccessSelection>(INITIAL_AWS_ACCESS);
  const [validation, setValidation] = useState<SharedAwsValidation | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const selected = selectedId ? items.find((item) => item.id === selectedId) : items[0];

  const refresh = useCallback(async () => {
    try {
      const result = await api.sharedAwsConnections();
      setItems(result.items.filter((item) => item.connection_kind === "shared_aws"));
      setAvailability("enabled");
      setLoadError("");
      onAvailabilityChange?.("enabled");
    } catch (cause) {
      const state = sharedAwsFailureState(cause);
      setAvailability(state);
      setLoadError(cause instanceof Error ? cause.message : "Shared AWS connection service is unavailable");
      onAvailabilityChange?.(state);
    }
  }, [onAvailabilityChange]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!selected) return;
    const config = connection?.configuration;
    const mode = config?.coverage_mode ?? selected.coverage_mode ?? "selected";
    const regions = config?.regions ?? selected.regions ?? ["us-east-1"];
    setAttachmentAccess({
      coverageMode: mode === "automatic" || mode === "selected-resource" ? mode : "selected",
      selectedResource: config?.selected_resource ?? selected.selected_resource,
      deploymentRegion: config?.deployment_region ?? selected.deployment_region ?? regions[0] ?? "us-east-1",
      regionText: regions.join(", "),
      scopes: connection?.declared_scopes ?? (selected.validated_scopes.includes("aws.bedrock_agents") ? ["aws.bedrock_agents"] : []),
    });
  }, [selected?.id, connection?.id]);

  const refreshValidation = useSharedStatusPolling({
    identity: selected?.id,
    read: (id) => api.sharedAwsValidation(id),
    pending: (result) => ["queued", "running"].includes(result.job_state ?? ""),
    accept: (result) => {
      setValidation(result);
      onProgress?.("verify", result.validation_summary ?? "Checking AWS access");
      if (result.job_state === "succeeded" || result.job_state === "failed") void refresh();
    },
    reject: (cause) => {
      setValidation(null);
      setError(cause instanceof Error ? cause.message : "Validation status is unavailable");
    },
  });

  async function perform(action: string, task: () => Promise<void>) {
    if (busy) return;
    setBusy(action);
    setMessage("");
    setError("");
    try {
      await task();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Shared AWS request failed");
    } finally {
      setBusy(null);
    }
  }

  function create(event: FormEvent) {
    event.preventDefault();
    void perform("create", async () => {
      const config = sharedAwsConfiguration(creationAccess);
      const created = await api.createSharedAwsConfiguration({ account_id: accountId.trim(), partition, ...config });
      await refresh();
      setSelectedId(created.id);
      setMessage("Shared connection registered. Deploy its read-only role, then validate.");
      onProgress?.("grant", "Deploy the read-only role in AWS");
    });
  }

  function download() {
    if (!selected) return;
    void perform("download", async () => {
      const blob = await api.sharedAwsTemplate(selected.id);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `transilience-shared-aws-${selected.external_account_id}.yaml`;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }

  function validate() {
    if (!selected) return;
    void perform("validate", async () => {
      await api.validateSharedAws(selected.id);
      setValidation({
        job_state: "queued", health_state: "unknown", credential_state: "unknown",
        job_error_code: null, validation_summary: null,
      });
      setMessage("Validation started. Status will update here.");
      onProgress?.("verify", "Verifying AWS access");
      await refreshValidation();
    });
  }

  function probe() {
    if (!selected) return;
    void perform("probe", async () => {
      const result = await api.probeSharedAws(selected.id, sharedAwsConfiguration(attachmentAccess).deployment_region);
      setMessage(`Scoped ${result.scope} read passed in ${result.region}; sampled ${result.sample_count} agent record(s).`);
    });
  }

  function useInDenali() {
    if (!selected) return;
    void perform("use", async () => {
      const attached = await api.useSharedAwsConfiguration(selected.id, sharedAwsConfiguration(attachmentAccess));
      await onChanged();
      await onAttached?.(attached);
      setMessage("AWS is selected in Denali. Verify access, then collect the approved Regions and evidence planes.");
    });
  }

  function disable() {
    if (!selected || !window.confirm("Disable AWS access for all applications in this organization? Existing sessions remain valid until they expire. Disconnecting only from Denali is available in its connection detail.")) return;
    void perform("disable", async () => {
      await api.disableSharedAws(selected.id);
      await refresh();
      setMessage("Shared connection disabled. Previously issued sessions expire within 15 minutes.");
    });
  }

  if (availability === "not_enabled" || availability === "checking") return null;
  return <section id="shared-aws-onboarding" className="panel shared-aws-pilot" aria-label="Shared AWS onboarding">
    <div className="shared-aws-pilot-heading">
      <div><h3>Grant AWS access</h3><p>Choose the exact AWS Regions and read-only evidence to connect. Deploy the generated role in your account, then verify access.</p></div>
      <button type="button" disabled={busy !== null} onClick={() => { void refresh(); void refreshValidation(); }}>Check status</button>
    </div>
    {availability === "error" && <p className="shared-aws-pilot-error" role="alert">Shared AWS onboarding is unavailable: {loadError}. No Denali-managed AWS connection was created. Retry here or ask an operator to check the Platform service.</p>}
    {availability === "enabled" && canWrite && !connection && <form className="shared-aws-pilot-form" onSubmit={create}>
      <label>AWS account ID<input required inputMode="numeric" pattern="[0-9]{12}" maxLength={12} value={accountId} onChange={(event) => setAccountId(event.target.value)} placeholder="123456789012" /></label>
      <label>AWS partition<select value={partition} onChange={(event) => setPartition(event.target.value as typeof partition)}><option value="aws">AWS</option><option value="aws-us-gov">AWS GovCloud</option><option value="aws-cn">AWS China</option></select></label>
      <AwsAccessFields value={creationAccess} onChange={setCreationAccess} allowedScopes={SHARED_AWS_SCOPES.map((scope) => scope.id)} automatic exact={supportedCoverageModes.includes("selected-resource")} />
      <button className="primary-action" disabled={busy !== null}>Register shared AWS</button>
    </form>}
    {availability === "enabled" && items.length > 0 && <div className="shared-aws-pilot-detail">
      <label>Authorized connection<select value={selected?.id ?? ""} disabled={busy !== null || !!connection} onChange={(event) => { setSelectedId(event.target.value); setValidation(null); }}>
        {items.map((item) => <option key={item.id} value={item.id}>{item.external_account_id} · {item.availability}</option>)}
      </select></label>
      {selected && <><p>Account {selected.external_account_id} · {selected.partition} · {selected.availability}</p>
        <AwsAccessFields value={attachmentAccess} onChange={setAttachmentAccess} allowedScopes={connection?.declared_scopes ?? selected.validated_scopes} automatic={selected.coverage_mode === "automatic" || connection?.configuration.coverage_mode === "automatic"} exact={selected.coverage_mode === "selected-resource" || connection?.configuration.coverage_mode === "selected-resource"} locked={!!connection || busy !== null || selected.coverage_mode === "selected-resource"} />
        {connection && <p>This attachment keeps its saved Regions and scopes. Changing organization-wide role permissions does not expand it.</p>}
        {canWrite && <div className="shared-aws-pilot-actions">
          <button type="button" disabled={busy !== null} onClick={download}>Download role template</button>
          <button type="button" disabled={busy !== null || selected.availability === "disabled"} onClick={validate}>Validate</button>
          {attachmentAccess.coverageMode !== "selected-resource" && attachmentAccess.scopes.includes("aws.bedrock_agents") && <button type="button" disabled={busy !== null || selected.availability !== "ready"} onClick={probe}>Test scoped AWS read</button>}
          <button type="button" disabled={busy !== null || selected.availability !== "ready" || (attachmentAccess.coverageMode !== "selected-resource" && attachmentAccess.scopes.length === 0)} onClick={useInDenali}>Use in Denali</button>
        </div>}
        {canWrite && <details className="connection-organization-access"><summary>Organization-wide access</summary><p>This affects every application using this AWS connection.</p><button type="button" disabled={busy !== null || selected.availability === "disabled"} onClick={disable}>Disable access for all applications</button></details>}
        {validation && <p role="status">Validation: {validation.job_state ?? "not started"} · {validation.health_state}{validation.validation_summary ? ` · ${validation.validation_summary}` : ""}</p>}
      </>}
    </div>}
    {message && <p className="shared-aws-pilot-message" role="status">{message}</p>}
    {error && <p className="shared-aws-pilot-error" role="alert">{error}</p>}
  </section>;
}
