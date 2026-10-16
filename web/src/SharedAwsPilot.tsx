import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, type SharedAwsConnection, type SharedAwsValidation } from "./api";
import { sharedAwsFailureState, type SharedAwsAvailability } from "./connectionOnboarding";
import { platformConnectionId, type SharedConnectionAdapterProps } from "./sharedConnectionAdapter";
import { useSharedStatusPolling } from "./useSharedStatusPolling";
import { INITIAL_AWS_ACCESS, SHARED_AWS_SCOPES, sharedAwsConfiguration, type AwsAccessSelection } from "./sharedAwsOnboarding";
import { ConnectorEmptyState, ConnectorErrorState, ConnectorLoadingState, EvidenceScopePicker } from "./ConnectorUi";

function AwsAccessFields({ value, onChange, allowedScopes, automatic, exact = false, locked = false }: {
  value: AwsAccessSelection; onChange: (value: AwsAccessSelection) => void; allowedScopes: string[]; automatic: boolean; exact?: boolean; locked?: boolean;
}) {
  return <fieldset className="connection-access-selection connector-form-section connector-access-options" disabled={locked}>
    <legend>Regions and read-only evidence</legend>
    <label className="connector-field">Region coverage<select value={value.coverageMode} onChange={(event) => onChange({ ...value, coverageMode: event.target.value as AwsAccessSelection["coverageMode"] })}><option value="selected">Selected Regions</option>{automatic && <option value="automatic">All enabled Regions</option>}{exact && <option value="selected-resource">One exact Zip Lambda and execution role</option>}</select></label>
    {value.coverageMode !== "selected-resource" && <label className="connector-field">Deployment Region<input required value={value.deploymentRegion} onChange={(event) => onChange({ ...value, deploymentRegion: event.target.value })} /></label>}
    {value.coverageMode === "selected" && <label className="connector-field">Regions (up to 40, separated by commas)<input required value={value.regionText} onChange={(event) => onChange({ ...value, regionText: event.target.value })} /></label>}
    {value.coverageMode === "selected-resource" ? <>
      <p>Read configuration and IAM policy evidence for one pinned Zip Lambda only. No account discovery, source download, invocation, or account-wide health claim. Platform creates a separate read-only role.</p>
      {(["function_arn", "execution_role_arn", "expected_model_id"] as const).map((field) => <label className="connector-field" key={field}>{field === "function_arn" ? "Exact Lambda ARN (without alias or version)" : field === "execution_role_arn" ? "Lambda execution role ARN" : "Expected Bedrock model ID or ARN"}<input required maxLength={300} value={value.selectedResource?.[field] ?? ""} onChange={(event) => onChange({ ...value, selectedResource: { kind: "lambda_zip", function_arn: "", execution_role_arn: "", expected_model_id: "", ...value.selectedResource, [field]: event.target.value } })} /></label>)}
    </> : <EvidenceScopePicker scopes={SHARED_AWS_SCOPES.filter((scope) => allowedScopes.includes(scope.id)).map((scope) => scope.id)} selected={value.scopes} onChange={(scopes) => onChange({ ...value, scopes })} disabled={locked} help="Only the evidence you select is included. Existing access is never expanded automatically." />}
  </fieldset>;
}

type SharedAwsPilotProps = SharedConnectionAdapterProps & { onAvailabilityChange?: (availability: SharedAwsAvailability) => void; supportedCoverageModes?: string[] };

export function SharedAwsPilot(props: SharedAwsPilotProps) {
  return <SharedAwsPanel key={props.connection?.id ?? "new"} {...props} />;
}

function SharedAwsPanel({ canWrite, onChanged, onAvailabilityChange, connection, onAttached, onProgress, supportedCoverageModes = ["selected", "automatic"] }: SharedAwsPilotProps) {
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
  const [loading, setLoading] = useState(true);
  const [statusLoading, setStatusLoading] = useState(false);
  const [statusError, setStatusError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const mounted = useRef(true);
  const listingGeneration = useRef(0);
  const actionGeneration = useRef(0);
  const actionPending = useRef(false);
  const selected = selectedId ? items.find((item) => item.id === selectedId) : items[0];
  const currentSource = useRef(selected?.id);
  currentSource.current = selected?.id;
  const checkingStatus = Boolean(selected) && (statusLoading || (!validation && !statusError));
  const blocked = busy !== null || loading || checkingStatus || Boolean(statusError);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; listingGeneration.current += 1; actionGeneration.current += 1; };
  }, []);

  const refresh = useCallback(async () => {
    const generation = ++listingGeneration.current;
    setLoading(true);
    try {
      const result = await api.sharedAwsConnections();
      if (!mounted.current || generation !== listingGeneration.current) return;
      setItems(result.items.filter((item) => item.connection_kind === "shared_aws"));
      setAvailability("enabled");
      setLoadError("");
      onAvailabilityChange?.("enabled");
    } catch (cause) {
      if (!mounted.current || generation !== listingGeneration.current) return;
      const state = sharedAwsFailureState(cause);
      setAvailability(state);
      setLoadError(cause instanceof Error ? cause.message : "Shared AWS connection service is unavailable");
      onAvailabilityChange?.(state);
    } finally { if (mounted.current && generation === listingGeneration.current) setLoading(false); }
  }, [onAvailabilityChange]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => { setValidation(null); setStatusError(""); }, [selected?.id]);
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
    read: async (id) => {
      if (mounted.current && currentSource.current === id) setStatusLoading(true);
      return { id, value: await api.sharedAwsValidation(id) };
    },
    pending: (result) => ["queued", "running"].includes(result.value.job_state ?? ""),
    accept: ({ id, value: result }) => {
      if (currentSource.current !== id) return;
      setStatusLoading(false); setStatusError("");
      setValidation(result);
      onProgress?.("verify", result.validation_summary ?? "Checking AWS access");
      if (result.job_state === "succeeded" || result.job_state === "failed") void refresh();
    },
    reject: (cause) => {
      setStatusLoading(false);
      setValidation(null);
      setStatusError(cause instanceof Error ? cause.message : "Validation status is unavailable");
    },
  });

  async function perform(action: string, task: (current: () => boolean) => Promise<void>) {
    if (actionPending.current || !canWrite) return;
    actionPending.current = true;
    const generation = ++actionGeneration.current;
    const source = currentSource.current;
    const current = () => mounted.current && generation === actionGeneration.current && currentSource.current === source;
    setBusy(action);
    setMessage("");
    setError("");
    try {
      await task(current);
    } catch (cause) {
      if (current()) setError(cause instanceof Error ? cause.message : "Shared AWS request failed");
    } finally {
      if (generation === actionGeneration.current) { actionPending.current = false; if (mounted.current) setBusy(null); }
    }
  }

  function create(event: FormEvent) {
    event.preventDefault();
    void perform("create", async (current) => {
      const config = sharedAwsConfiguration(creationAccess);
      const created = await api.createSharedAwsConfiguration({ account_id: accountId.trim(), partition, ...config });
      if (!current()) return;
      await refresh();
      if (!mounted.current) return;
      setSelectedId(created.id);
      setShowCreate(false);
      setMessage("Shared connection registered. Deploy its read-only role, then validate.");
      onProgress?.("grant", "Deploy the read-only role in AWS");
    });
  }

  function download() {
    if (!selected) return;
    void perform("download", async (current) => {
      const blob = await api.sharedAwsTemplate(selected.id);
      if (!current()) return;
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
    void perform("validate", async (current) => {
      await api.validateSharedAws(selected.id);
      if (!current()) return;
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
    void perform("probe", async (current) => {
      const result = await api.probeSharedAws(selected.id, sharedAwsConfiguration(attachmentAccess).deployment_region);
      if (!current()) return;
      setMessage(`Scoped ${result.scope} read passed in ${result.region}; sampled ${result.sample_count} agent record(s).`);
    });
  }

  function useInDenali() {
    if (!selected) return;
    void perform("use", async (current) => {
      const attached = await api.useSharedAwsConfiguration(selected.id, sharedAwsConfiguration(attachmentAccess));
      if (!current()) return;
      await onChanged();
      if (!current()) return;
      await onAttached?.(attached);
      setMessage("AWS is selected in Denali. Verify access, then collect the approved Regions and evidence planes.");
    });
  }

  function disable() {
    if (!selected || !window.confirm("Disable AWS access for all applications in this organization? Existing sessions remain valid until they expire. Disconnecting only from Denali is available in its connection detail.")) return;
    void perform("disable", async (current) => {
      await api.disableSharedAws(selected.id);
      if (!current()) return;
      await refresh();
      setMessage("Shared connection disabled. Previously issued sessions expire within 15 minutes.");
    });
  }

  if (availability === "not_enabled") return <section className="panel shared-aws-pilot" aria-label="Shared AWS onboarding">
    <ConnectorEmptyState title="AWS access is unavailable"><p>Reusable AWS access is not enabled for this organization right now. Existing connections remain unchanged; no native fallback was created.</p><div className="connector-actions"><button type="button" disabled={loading} onClick={() => void refresh()}>{loading ? "Checking access…" : "Check again"}</button></div></ConnectorEmptyState>
    {loading && <ConnectorLoadingState label="Checking AWS availability" compact />}
  </section>;
  if (availability === "checking") return <ConnectorLoadingState label="Loading AWS access" detail="Checking the reusable AWS connections available to this organization." />;
  return <section id="shared-aws-onboarding" className="panel shared-aws-pilot" aria-label="Shared AWS onboarding">
    <div className="shared-aws-pilot-heading">
      <div><h3>{items.length ? "Choose AWS access" : "Grant AWS access"}</h3><p>Reuse approved access, or set up a read-only role for another account. Regions and evidence stay explicitly selected.</p></div>
      <button type="button" disabled={busy !== null || loading || statusLoading} onClick={() => { void refresh(); void refreshValidation(); }}>Check status</button>
    </div>
    {availability === "error" && <ConnectorErrorState message={`AWS access could not be loaded: ${loadError}. No fallback connection was created.`} onRetry={() => void refresh()} retrying={loading} />}
    {loading && <ConnectorLoadingState label="Refreshing AWS access" compact />}
    {availability === "enabled" && items.length > 0 && <div className="shared-aws-pilot-detail">
      <label className="connector-field">Authorized connection<select value={selected?.id ?? ""} disabled={busy !== null || loading || !!connection} onChange={(event) => { setSelectedId(event.target.value); setValidation(null); setStatusError(""); setError(""); setMessage(""); }}>
        {items.map((item) => <option key={item.id} value={item.id}>{item.external_account_id} · {item.availability}</option>)}
      </select></label>
      {selected && <><p>Account {selected.external_account_id} · {selected.partition} · {selected.availability}</p>
        {checkingStatus && <ConnectorLoadingState label="Checking AWS access status" compact />}
        {statusError && <ConnectorErrorState message={statusError} onRetry={() => void refreshValidation()} retrying={statusLoading} />}
        <AwsAccessFields value={attachmentAccess} onChange={setAttachmentAccess} allowedScopes={connection?.declared_scopes ?? selected.validated_scopes} automatic={selected.coverage_mode === "automatic" || connection?.configuration.coverage_mode === "automatic"} exact={selected.coverage_mode === "selected-resource" || connection?.configuration.coverage_mode === "selected-resource"} locked={!!connection || blocked || selected.coverage_mode === "selected-resource"} />
        {connection && <p>This attachment keeps its saved Regions and scopes. Changing organization-wide role permissions does not expand it.</p>}
        {canWrite && <div className="shared-aws-pilot-actions connector-actions">
          <button type="button" disabled={blocked} onClick={download}>Download role template</button>
          <button type="button" disabled={blocked || selected.availability === "disabled"} onClick={validate}>Validate</button>
          {attachmentAccess.coverageMode !== "selected-resource" && attachmentAccess.scopes.includes("aws.bedrock_agents") && <button type="button" disabled={blocked || selected.availability !== "ready"} onClick={probe}>Test scoped AWS read</button>}
          <button type="button" disabled={blocked || selected.availability !== "ready" || (attachmentAccess.coverageMode !== "selected-resource" && attachmentAccess.scopes.length === 0)} onClick={useInDenali}>Use in Denali</button>
        </div>}
        {canWrite && <details className="connection-organization-access"><summary>Organization-wide access</summary><p>This affects every application using this AWS connection.</p><button type="button" disabled={blocked || selected.availability === "disabled"} onClick={disable}>Disable access for all applications</button></details>}
        {validation && <p role="status">Validation: {validation.job_state ?? "not started"} · {validation.health_state}{validation.validation_summary ? ` · ${validation.validation_summary}` : ""}</p>}
      </>}
    </div>}
    {availability === "enabled" && connection && !selected && !loading && <ConnectorEmptyState title="The original AWS connection is unavailable">Its saved account, Regions and evidence have not been changed.</ConnectorEmptyState>}
    {availability === "enabled" && !items.length && !loading && !connection && <ConnectorEmptyState title="No reusable AWS access yet">Register an account below, review the generated role and grant access in AWS.</ConnectorEmptyState>}
    {availability === "enabled" && canWrite && !connection && <div className="connector-access-options">
      {items.length > 0 && <button className="connector-access-expander" type="button" aria-expanded={showCreate} disabled={busy !== null || loading} onClick={() => setShowCreate(!showCreate)}>{showCreate ? "Cancel new AWS setup" : "Set up new AWS access"}</button>}
      {(!items.length || showCreate) && <form className="shared-aws-pilot-form connector-form" onSubmit={create}>
        <label className="connector-field">AWS account ID<input required disabled={busy !== null || loading} inputMode="numeric" pattern="[0-9]{12}" maxLength={12} value={accountId} onChange={(event) => setAccountId(event.target.value)} placeholder="123456789012" /></label>
        <label className="connector-field">AWS partition<select disabled={busy !== null || loading} value={partition} onChange={(event) => setPartition(event.target.value as typeof partition)}><option value="aws">AWS</option><option value="aws-us-gov">AWS GovCloud</option><option value="aws-cn">AWS China</option></select></label>
        <AwsAccessFields value={creationAccess} onChange={setCreationAccess} allowedScopes={SHARED_AWS_SCOPES.map((scope) => scope.id)} automatic exact={supportedCoverageModes.includes("selected-resource")} locked={busy !== null || loading} />
        <div className="connector-actions"><button className="primary-action" disabled={busy !== null || loading}>Register shared AWS</button></div>
      </form>}
    </div>}
    {busy && <ConnectorLoadingState label={busy === "create" ? "Registering AWS access" : busy === "download" ? "Preparing the AWS role template" : busy === "use" ? "Attaching AWS in Denali" : busy === "disable" ? "Updating organization access" : "Checking AWS access"} compact />}
    {message && <p className="shared-aws-pilot-message" role="status">{message}</p>}
    {error && <ConnectorErrorState message={error} />}
  </section>;
}
