import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, type SharedMicrosoftConnection, type SharedMicrosoftProvider, type SharedMicrosoftStatus } from "./api";
import { sharedGcpNotEnabled } from "./sharedGcpOnboarding";
import { SHARED_AZURE_SCOPES, SHARED_ENTRA_SCOPES, microsoftConsentUrl, microsoftTenantId, parseSharedAzureSubscriptions, sharedMicrosoftReady } from "./sharedMicrosoftOnboarding";
import { platformConnectionId, type SharedConnectionAdapterProps } from "./sharedConnectionAdapter";
import { useSharedStatusPolling } from "./useSharedStatusPolling";
import { ConnectorEmptyState, ConnectorErrorState, ConnectorLoadingState, EvidenceScopePicker } from "./ConnectorUi";

type SharedMicrosoftPilotProps = SharedConnectionAdapterProps & { provider: SharedMicrosoftProvider };

export function SharedMicrosoftPilot(props: SharedMicrosoftPilotProps) {
  return <SharedMicrosoftPanel key={`${props.provider}:${props.connection?.id ?? "new"}`} {...props} />;
}

function SharedMicrosoftPanel({ provider, canWrite, onChanged, connection, onAttached, onProgress }: SharedMicrosoftPilotProps) {
  const azure = provider === "azure";
  const label = azure ? "Azure" : "Microsoft Entra";
  const allScopes = azure ? SHARED_AZURE_SCOPES : SHARED_ENTRA_SCOPES;
  const [enabled, setEnabled] = useState(false);
  const [items, setItems] = useState<SharedMicrosoftConnection[]>([]);
  const [selectedId, setSelectedId] = useState(() => platformConnectionId(connection));
  const [name, setName] = useState(`Shared ${label}`);
  const [tenant, setTenant] = useState("");
  const [subscriptions, setSubscriptions] = useState("");
  const [scopes, setScopes] = useState(allScopes);
  const [status, setStatus] = useState<SharedMicrosoftStatus | null>(null);
  const [consentUrl, setConsentUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState("");
  const [statusLoading, setStatusLoading] = useState(false);
  const [statusError, setStatusError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const mounted = useRef(true);
  const listingGeneration = useRef(0);
  const actionGeneration = useRef(0);
  const actionPending = useRef(false);
  const creation = useRef<{ definition: string; id: string } | null>(null);
  const selected = selectedId ? items.find((item) => item.id === selectedId) : items[0];
  const identity = selected ? `${provider}:${selected.id}` : undefined;
  const currentSource = useRef(identity);
  currentSource.current = identity;
  const checkingStatus = Boolean(selected) && (statusLoading || (!status && !statusError));
  const blocked = busy || loading || checkingStatus || Boolean(listError || statusError);
  const attachmentScopes = connection?.declared_scopes ?? (azure ? selected?.validated_scopes ?? [] : SHARED_ENTRA_SCOPES);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; listingGeneration.current += 1; actionGeneration.current += 1; };
  }, []);

  const refresh = useCallback(async () => {
    const generation = ++listingGeneration.current;
    setLoading(true);
    try {
      const result = await api.sharedMicrosoftConnections(provider);
      if (!mounted.current || generation !== listingGeneration.current) return;
      setItems(result.items); setEnabled(true); setListError("");
    } catch (cause) {
      if (!mounted.current || generation !== listingGeneration.current) return;
      if (sharedGcpNotEnabled(cause)) { setEnabled(false); return; }
      setEnabled(true); setListError(cause instanceof Error ? cause.message : `Shared ${label} is unavailable`);
    } finally { if (mounted.current && generation === listingGeneration.current) setLoading(false); }
  }, [provider, label]);
  const readStatus = useSharedStatusPolling({
    identity,
    read: async (source) => {
      if (mounted.current && currentSource.current === source) setStatusLoading(true);
      const [sourceProvider, sourceId] = source.split(":") as [SharedMicrosoftProvider, string];
      return { identity: source, value: await api.sharedMicrosoftStatus(sourceProvider, sourceId) };
    },
    pending: (result) => ["queued", "running"].includes(result.value.job_state ?? ""),
    accept: ({ identity: source, value: result }) => {
      if (currentSource.current !== source) return;
      setStatusLoading(false); setStatusError("");
      setStatus(result);
      onProgress?.(result.setup_state === "ready" ? "verify" : "grant");
      if (result.job_state === "succeeded" || result.job_state === "failed") void refresh();
    },
    reject: (cause) => { setStatusLoading(false); setStatus(null); setStatusError(cause instanceof Error ? cause.message : "Microsoft status is unavailable"); },
  });
  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    setConsentUrl(""); setStatus(null); setStatusError("");
  }, [identity]);

  async function perform(task: (current: () => boolean) => Promise<void>) {
    if (actionPending.current || !canWrite) return;
    actionPending.current = true;
    const generation = ++actionGeneration.current;
    const source = currentSource.current;
    const current = () => mounted.current && generation === actionGeneration.current && currentSource.current === source;
    setBusy(true); setError(""); setMessage("");
    try { await task(current); }
    catch (cause) { if (current()) setError(cause instanceof Error ? cause.message : "Shared Microsoft request failed"); }
    finally { if (generation === actionGeneration.current) { actionPending.current = false; if (mounted.current) setBusy(false); } }
  }
  function create(event: FormEvent) {
    event.preventDefault();
    void perform(async (current) => {
      const input = { display_name: name.trim(), tenant_id: microsoftTenantId(tenant), declared_scopes: [...scopes].sort(), ...(azure ? { subscriptions: parseSharedAzureSubscriptions(subscriptions) } : {}) };
      const definition = JSON.stringify(input);
      if (creation.current?.definition !== definition) creation.current = { definition, id: crypto.randomUUID() };
      const result = await api.createSharedMicrosoft(provider, { ...input, request_id: creation.current.id });
      if (!current()) return;
      await refresh(); if (!mounted.current) return;
      setSelectedId(result.id); setShowCreate(false);
      setMessage("Plan created. Review and grant Microsoft consent. Access status refreshes automatically when you return.");
      onProgress?.("grant");
    });
  }
  function download() {
    if (!selected) return;
    void perform(async (current) => {
      const blob = await api.sharedAzureScript(selected.id);
      if (!current()) return;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = `transilience-azure-${selected.id}.sh`; anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setMessage("Review this script. Run it yourself in Azure Cloud Shell only after approving Reader assignments to the exact subscriptions and application it names. Denali does not execute it.");
    });
  }
  if (loading && !enabled && !listError) return <ConnectorLoadingState label={`Loading ${label} access`} detail="Checking reusable connections and consent status for this organization." />;
  if (!enabled) return <section className="panel shared-aws-pilot" aria-label={`Shared ${label} onboarding`}>
    <ConnectorEmptyState title={`${label} access is unavailable`}><p>Reusable {label} access is not enabled for this organization right now. Existing connections remain unchanged; no native fallback was created.</p><div className="connector-actions"><button type="button" disabled={loading} onClick={() => void refresh()}>{loading ? "Checking access…" : "Check again"}</button></div></ConnectorEmptyState>
    {loading && <ConnectorLoadingState label={`Checking ${label} availability`} compact />}
  </section>;
  return <section className="panel shared-aws-pilot" aria-label={`Shared ${label} onboarding`}>
    <div className="shared-aws-pilot-heading"><div><h3>{items.length ? "Choose" : "Grant"} {label} access</h3><p>Reuse an approved connection, or review new read-only access. This view checks access status when you return.</p></div><button type="button" disabled={busy || loading || statusLoading} onClick={() => { void refresh(); void readStatus(); }}>Check status</button></div>
    {listError && <ConnectorErrorState message={`${listError}. No fallback connection was created.`} onRetry={() => void refresh()} retrying={loading} />}
    {loading && <ConnectorLoadingState label={`Refreshing ${label} access`} compact />}
    {selected && <div className="shared-aws-pilot-detail">
      <label className="connector-field">Authorized connection<select value={selected.id} disabled={busy || loading || !!connection} onChange={(event) => { setSelectedId(event.target.value); setStatus(null); setStatusError(""); setConsentUrl(""); setError(""); setMessage(""); }}>{items.map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.availability}</option>)}</select></label>
      <p>Tenant {selected.tenant_id}{azure && ` · ${selected.subscriptions?.map((item) => item.name === item.id ? item.id : `${item.name} (${item.id})`).join(" · ")}`}</p>
      {checkingStatus ? <ConnectorLoadingState label={`Checking ${label} access status`} compact /> : <p role="status">{status?.setup_state ?? selected.setup_state} · {status?.job_state ?? "idle"} · {status?.health_state ?? selected.health_state}</p>}
      {statusError && <ConnectorErrorState message={statusError} onRetry={() => void readStatus()} retrying={statusLoading} />}
      {canWrite && <div className="shared-aws-pilot-actions connector-actions">
        <button disabled={blocked || selected.availability === "disabled"} onClick={() => void perform(async (current) => { const launch = await api.startSharedMicrosoftSetup(provider, selected.id); if (!current()) return; setConsentUrl(microsoftConsentUrl(launch.consent_url, selected.tenant_id, provider, azure ? { clientId: selected.application_client_id ?? "", callbackUrl: launch.callback_url ?? "" } : undefined)); })}>Prepare Microsoft admin consent</button>
        {consentUrl && <a href={consentUrl} target="_blank" rel="noopener noreferrer">Review and grant Microsoft consent</a>}
        {azure && <button disabled={blocked || selected.availability === "disabled"} onClick={download}>Download Reader setup script</button>}
        <button disabled={blocked || selected.availability === "disabled" || ["queued", "running"].includes(status?.job_state ?? "")} onClick={() => void perform(async (current) => { await api.validateSharedMicrosoft(provider, selected.id); if (!current()) return; onProgress?.("verify"); await readStatus(); })}>Verify read-only access</button>
        <button disabled={blocked || !sharedMicrosoftReady(selected, attachmentScopes)} onClick={() => void perform(async (current) => { const attached = await api.useSharedMicrosoft(provider, selected.id, attachmentScopes); if (!current()) return; await onChanged(); if (!current()) return; await onAttached?.(attached); if (current()) setMessage("Attached in Denali. Its existing validation and collection actions use durable jobs."); })}>Use in Denali</button>
      </div>}
      {canWrite && <details className="connection-organization-access"><summary>Organization-wide access</summary><p>These actions affect every application using this Microsoft connection.</p><div className="shared-aws-pilot-actions">
        <button disabled={blocked || selected.availability === "disabled"} onClick={() => { if (window.confirm(`Disable this shared ${label} connection for all apps? Microsoft consent and Azure role assignments remain until removed separately.`)) void perform(async (current) => { await api.disableSharedMicrosoft(provider, selected.id); if (current()) await refresh(); }); }}>Disable access for all applications</button>
        {selected.availability === "disabled" && <button className="danger-action" disabled={blocked} onClick={() => {
          const confirmation = window.prompt(`Type “${selected.display_name}” to delete this disabled shared plan. Provider grants, Denali references and collected evidence remain; remove them separately.`);
          if (confirmation === null) return;
          void perform(async (current) => { if (confirmation !== selected.display_name) throw new Error("Shared connection name confirmation failed"); await api.deleteSharedMicrosoft(provider, selected.id, confirmation); if (!current()) return; await refresh(); if (mounted.current) setMessage("Shared plan deleted. Disable and delete Denali configuration separately."); });
        }}>Delete disabled shared plan</button>}
      </div></details>}
      <p className="connector-field-hint">Azure covers at most 24 hours; Entra covers at most 7 days per run. Validation proves access, not collection or a risk verdict.</p>
    </div>}
    {connection && !selected && !loading && !listError && <ConnectorEmptyState title={`The original ${label} connection is unavailable`}>Its saved tenant and evidence selection has not been changed.</ConnectorEmptyState>}
    {!items.length && !loading && !listError && !connection && <ConnectorEmptyState title={`No reusable ${label} access yet`}>Register the approved Microsoft tenant below, then review the consent and role-assignment steps.</ConnectorEmptyState>}
    {canWrite && !connection && !listError && <div className="connector-access-options">
      {items.length > 0 && <button className="connector-access-expander" type="button" aria-expanded={showCreate} disabled={busy || loading} onClick={() => setShowCreate(!showCreate)}>{showCreate ? `Cancel new ${label} setup` : `Set up new ${label} access`}</button>}
      {(!items.length || showCreate) && <form className="shared-aws-pilot-form connector-form" onSubmit={create}>
        <label className="connector-field">Name<input required disabled={busy || loading} maxLength={100} pattern="[A-Za-z0-9 _.()-]+" value={name} onChange={(event) => setName(event.target.value)} /></label>
        <label className="connector-field">Microsoft tenant UUID<input required disabled={busy || loading} value={tenant} onChange={(event) => setTenant(event.target.value)} /><small className="connector-field-hint">Use the Microsoft tenant/subscriptions approved for this organization.</small></label>
        {azure && <label className="connector-field connector-field-wide">Azure subscription UUIDs (maximum 8)<textarea required disabled={busy || loading} value={subscriptions} onChange={(event) => setSubscriptions(event.target.value)} placeholder="One exact subscription UUID per line" /></label>}
        {azure ? <EvidenceScopePicker scopes={allScopes} selected={scopes} onChange={setScopes} disabled={busy || loading} help="Choose the read-only evidence for this new plan. Existing connections keep their saved selection." /> : <p className="connector-field-hint connector-form-section">Fixed Microsoft Graph application bundle: Directory.Read.All and AuditLog.Read.All for AI applications, permissions, sign-ins and application-management audits. Microsoft grants the registered bundle together.</p>}
        <div className="connector-actions"><button className="primary-action" disabled={busy || loading || !scopes.length}>Create shared {label} plan</button></div>
      </form>}
    </div>}
    {busy && <ConnectorLoadingState label={`Updating ${label} access`} detail="Preparing your request. Consent and role changes remain explicit administrator actions." compact />}
    {message && <p role="status">{message}</p>}{error && <ConnectorErrorState message={`${error}. Shared failures never create a native fallback connection.`} />}
  </section>;
}
