import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, type SharedMicrosoftConnection, type SharedMicrosoftProvider, type SharedMicrosoftStatus } from "./api";
import { sharedGcpNotEnabled } from "./sharedGcpOnboarding";
import { SHARED_AZURE_SCOPES, SHARED_ENTRA_SCOPES, microsoftConsentUrl, microsoftTenantId, parseSharedAzureSubscriptions, sharedMicrosoftReady } from "./sharedMicrosoftOnboarding";

export function SharedMicrosoftPilot({ provider, canWrite, onChanged }: { provider: SharedMicrosoftProvider; canWrite: boolean; onChanged: () => Promise<void> }) {
  const azure = provider === "azure";
  const label = azure ? "Azure" : "Microsoft Entra";
  const allScopes = azure ? SHARED_AZURE_SCOPES : SHARED_ENTRA_SCOPES;
  const [enabled, setEnabled] = useState(false);
  const [items, setItems] = useState<SharedMicrosoftConnection[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [name, setName] = useState(`Shared ${label}`);
  const [tenant, setTenant] = useState("");
  const [subscriptions, setSubscriptions] = useState("");
  const [scopes, setScopes] = useState(allScopes);
  const [status, setStatus] = useState<SharedMicrosoftStatus | null>(null);
  const [consentUrl, setConsentUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const creation = useRef<{ definition: string; id: string } | null>(null);
  const selected = items.find((item) => item.id === selectedId) ?? items[0];
  const attachmentScopes = azure ? selected?.validated_scopes ?? [] : SHARED_ENTRA_SCOPES;

  const refresh = useCallback(async () => {
    try {
      const result = await api.sharedMicrosoftConnections(provider);
      setItems(result.items); setEnabled(true); setError("");
    } catch (cause) {
      if (sharedGcpNotEnabled(cause)) { setEnabled(false); return; }
      setEnabled(true); setError(cause instanceof Error ? cause.message : `Shared ${label} is unavailable`);
    }
  }, [provider, label]);
  const readStatus = useCallback(async (id: string) => {
    const result = await api.sharedMicrosoftStatus(provider, id);
    setStatus(result);
    await refresh();
  }, [provider, refresh]);
  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    setConsentUrl(""); setStatus(null);
    if (selected) void readStatus(selected.id).catch(() => setError("Shared Microsoft status is unavailable"));
  }, [selected?.id, readStatus]);
  useEffect(() => {
    if (!selected || !["queued", "running"].includes(status?.job_state ?? "")) return;
    const timer = window.setInterval(() => { void readStatus(selected.id).catch(() => setError("Status polling failed")); }, 3000);
    return () => window.clearInterval(timer);
  }, [selected?.id, status?.job_state, readStatus]);

  async function perform(task: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try { await task(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Shared Microsoft request failed"); }
    finally { setBusy(false); }
  }
  function create(event: FormEvent) {
    event.preventDefault();
    void perform(async () => {
      const input = { display_name: name.trim(), tenant_id: microsoftTenantId(tenant), declared_scopes: [...scopes].sort(), ...(azure ? { subscriptions: parseSharedAzureSubscriptions(subscriptions) } : {}) };
      const definition = JSON.stringify(input);
      if (creation.current?.definition !== definition) creation.current = { definition, id: crypto.randomUUID() };
      const result = await api.createSharedMicrosoft(provider, { ...input, request_id: creation.current.id });
      await refresh(); setSelectedId(result.id); await readStatus(result.id);
      setMessage("Plan created. Launch Microsoft consent, then return here and refresh to review its state.");
    });
  }
  function download() {
    if (!selected) return;
    void perform(async () => {
      const blob = await api.sharedAzureScript(selected.id);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = `transilience-azure-${selected.id}.sh`; anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setMessage("Review this script. Run it yourself in Azure Cloud Shell only after approving Reader assignments to the exact subscriptions and application it names. Denali does not execute it.");
    });
  }
  if (!enabled) return null;
  return <section className="panel shared-aws-pilot" aria-label={`Shared ${label} onboarding`}>
    <div className="shared-aws-pilot-heading"><div><span className="eyebrow">REUSABLE {label.toUpperCase()} CONNECTION</span><h3>Connect {label} once</h3><p>Platform owns Microsoft consent and read-only access. Each app receives tenant-bound metadata. Consent returns to Platform; return here manually and refresh.</p></div><button type="button" disabled={busy} onClick={() => void perform(async () => { await refresh(); if (selected) await readStatus(selected.id); })}>Refresh</button></div>
    {canWrite && <form className="shared-aws-pilot-form" onSubmit={create}>
      <label>Name<input required maxLength={100} pattern="[A-Za-z0-9 _.()-]+" value={name} onChange={(event) => setName(event.target.value)} /></label>
      <label>Microsoft tenant UUID<input required value={tenant} onChange={(event) => setTenant(event.target.value)} /></label>
      <p>Use the Microsoft tenant/subscriptions approved for this organization; ask your Platform admin if unavailable.</p>
      {azure && <label>Azure subscription UUIDs (maximum 8)<textarea required value={subscriptions} onChange={(event) => setSubscriptions(event.target.value)} placeholder="One exact subscription UUID per line" /></label>}
      {azure ? <fieldset><legend>Read-only evidence planes</legend>{allScopes.map((scope) => <label key={scope}><input type="checkbox" checked={scopes.includes(scope)} onChange={(event) => setScopes(event.target.checked ? [...scopes, scope] : scopes.filter((item) => item !== scope))} />{scope.replace("azure.", "").replaceAll("_", " ")}</label>)}</fieldset> : <p>Fixed Microsoft Graph application bundle: Directory.Read.All and AuditLog.Read.All for AI applications, permissions, sign-ins and application-management audits. Microsoft grants the registered bundle together.</p>}
      <button className="primary-action" disabled={busy || !scopes.length}>Create shared {label} plan</button>
    </form>}
    {selected && <div className="shared-aws-pilot-detail">
      <label>Shared connection<select value={selected.id} onChange={(event) => setSelectedId(event.target.value)}>{items.map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.availability}</option>)}</select></label>
      <p>Tenant {selected.tenant_id}{azure && ` · ${selected.subscriptions?.map((item) => item.name === item.id ? item.id : `${item.name} (${item.id})`).join(" · ")}`}</p>
      <p role="status">{status?.setup_state ?? selected.setup_state} · {status?.job_state ?? "idle"} · {status?.health_state ?? selected.health_state}</p>
      {canWrite && <div className="shared-aws-pilot-actions">
        <button disabled={busy || selected.availability === "disabled"} onClick={() => void perform(async () => { const launch = await api.startSharedMicrosoftSetup(provider, selected.id); setConsentUrl(microsoftConsentUrl(launch.consent_url, selected.tenant_id, provider, azure ? { clientId: selected.application_client_id ?? "", callbackUrl: launch.callback_url ?? "" } : undefined)); })}>Prepare Microsoft admin consent</button>
        {consentUrl && <a href={consentUrl} target="_blank" rel="noopener noreferrer">Review and grant Microsoft consent</a>}
        {azure && <button disabled={busy || selected.availability === "disabled"} onClick={download}>Download Reader setup script</button>}
        <button disabled={busy || selected.availability === "disabled" || ["queued", "running"].includes(status?.job_state ?? "")} onClick={() => void perform(async () => { await api.validateSharedMicrosoft(provider, selected.id); await readStatus(selected.id); })}>Validate read-only access</button>
        <button disabled={busy || !sharedMicrosoftReady(selected, attachmentScopes)} onClick={() => void perform(async () => { await api.useSharedMicrosoft(provider, selected.id, attachmentScopes); await onChanged(); setMessage("Attached in Denali. Its existing validation and collection actions use durable jobs."); })}>Use in Denali</button>
        <button disabled={busy || selected.availability === "disabled"} onClick={() => { if (window.confirm(`Disable this shared ${label} connection for all apps? Microsoft consent and Azure role assignments remain until removed separately.`)) void perform(async () => { await api.disableSharedMicrosoft(provider, selected.id); await refresh(); }); }}>Disable shared connection</button>
        {selected.availability === "disabled" && <button className="danger-action" disabled={busy} onClick={() => {
          const confirmation = window.prompt(`Type “${selected.display_name}” to delete this disabled shared plan. Provider grants, Denali references and collected evidence remain; remove them separately.`);
          if (confirmation === null) return;
          void perform(async () => { if (confirmation !== selected.display_name) throw new Error("Shared connection name confirmation failed"); await api.deleteSharedMicrosoft(provider, selected.id, confirmation); await refresh(); setMessage("Shared plan deleted. Disable and delete Denali configuration separately."); });
        }}>Delete disabled shared plan</button>}
      </div>}
      <p>Validation proves access, not collection or a risk verdict. Shared activity collection covers at most 24 hours per run.{azure && " Foundry agent runtime activity requires the existing native connection flow."}</p>
    </div>}
    {message && <p role="status">{message}</p>}{error && <p role="alert">{error}. Shared failures never create a native fallback connection.</p>}
  </section>;
}
