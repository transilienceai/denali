import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, type SharedGcpConnection, type SharedGcpStatus } from "./api";
import { parseSharedGcpProjects, sharedGcpCanRetry, sharedGcpNotEnabled } from "./sharedGcpOnboarding";
import { platformConnectionId, type SharedConnectionAdapterProps } from "./sharedConnectionAdapter";
import { useSharedStatusPolling } from "./useSharedStatusPolling";
import { ConnectorEmptyState, ConnectorErrorState, ConnectorLoadingState, EvidenceScopePicker } from "./ConnectorUi";

const SCOPES = ["gcp.vertex_ai", "gcp.agent_builder", "gcp.code_to_cloud", "gcp.ai_activity"];

export function SharedGcpPilot(props: SharedConnectionAdapterProps) {
  return <SharedGcpPanel key={props.connection?.id ?? "new"} {...props} />;
}

function SharedGcpPanel({ canWrite, onChanged, connection, onAttached, onProgress }: SharedConnectionAdapterProps) {
  const [enabled, setEnabled] = useState(false);
  const [items, setItems] = useState<SharedGcpConnection[]>([]);
  const [selectedId, setSelectedId] = useState(() => platformConnectionId(connection));
  const [name, setName] = useState("Shared Google Cloud");
  const [projectText, setProjectText] = useState("");
  const [scopes, setScopes] = useState<string[]>(SCOPES);
  const [status, setStatus] = useState<SharedGcpStatus | null>(null);
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
  const currentSource = useRef(selected?.id);
  currentSource.current = selected?.id;
  const checkingStatus = Boolean(selected) && (statusLoading || (!status && !statusError));
  const blocked = busy || loading || checkingStatus || Boolean(listError || statusError);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; listingGeneration.current += 1; actionGeneration.current += 1; };
  }, []);

  const refresh = useCallback(async () => {
    const generation = ++listingGeneration.current;
    setLoading(true);
    try {
      const result = await api.sharedGcpConnections();
      if (!mounted.current || generation !== listingGeneration.current) return;
      setItems(result.items);
      setEnabled(true);
      setListError("");
    } catch (cause) {
      if (!mounted.current || generation !== listingGeneration.current) return;
      if (sharedGcpNotEnabled(cause)) { setEnabled(false); return; }
      setEnabled(true);
      setListError(cause instanceof Error ? cause.message : "Shared Google Cloud is unavailable");
    } finally { if (mounted.current && generation === listingGeneration.current) setLoading(false); }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);
  const readStatus = useSharedStatusPolling({
    identity: selected?.id,
    read: async (id) => {
      if (mounted.current && currentSource.current === id) setStatusLoading(true);
      return { id, value: await api.sharedGcpStatus(id) };
    },
    pending: (result) => ["queued", "running"].includes(result.value.job_state ?? ""),
    accept: ({ id, value: result }) => {
      if (currentSource.current !== id) return;
      setStatusLoading(false); setStatusError("");
      setStatus(result);
      onProgress?.(result.setup_state === "ready" ? "verify" : "grant");
      if (result.job_state === "succeeded" || result.job_state === "failed") void refresh();
    },
    reject: (cause) => { setStatusLoading(false); setStatus(null); setStatusError(cause instanceof Error ? cause.message : "Google Cloud status is unavailable"); },
  });
  useEffect(() => { setStatus(null); setStatusError(""); }, [selected?.id]);

  async function perform(task: (current: () => boolean) => Promise<void>) {
    if (actionPending.current || !canWrite) return;
    actionPending.current = true;
    const generation = ++actionGeneration.current;
    const source = currentSource.current;
    const current = () => mounted.current && generation === actionGeneration.current && currentSource.current === source;
    setBusy(true); setError(""); setMessage("");
    try { await task(current); }
    catch (cause) { if (current()) setError(cause instanceof Error ? cause.message : "Shared Google Cloud request failed"); }
    finally { if (generation === actionGeneration.current) { actionPending.current = false; if (mounted.current) setBusy(false); } }
  }
  function create(event: FormEvent) {
    event.preventDefault();
    void perform(async (current) => {
      const projects = parseSharedGcpProjects(projectText);
      const declaredScopes = [...scopes].sort();
      const definition = JSON.stringify({ display_name: name.trim(), projects, declared_scopes: declaredScopes });
      if (creation.current?.definition !== definition) creation.current = { definition, id: crypto.randomUUID() };
      const result = await api.createSharedGcp({ request_id: creation.current.id, display_name: name.trim(), projects, declared_scopes: declaredScopes });
      if (!current()) return;
      await refresh(); if (!mounted.current) return;
      setSelectedId(result.id); setShowCreate(false);
      setMessage("Keyless principal provisioning queued. Review and apply its exact project setup script when ready, then validate.");
    });
  }
  function download() {
    if (!selected) return;
    void perform(async (current) => {
      const blob = await api.sharedGcpScript(selected.id);
      if (!current()) return;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = `transilience-gcp-${selected.id}.sh`; anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setMessage("Inspect the script before running it in Google Cloud Shell as an administrator of these exact projects. No service-account JSON key is needed.");
    });
  }
  if (loading && !enabled && !listError) return <ConnectorLoadingState label="Loading Google Cloud access" detail="Checking reusable projects and keyless setup plans for this organization." />;
  if (!enabled) return <section className="panel shared-aws-pilot" aria-label="Shared Google Cloud onboarding">
    <ConnectorEmptyState title="Google Cloud access is unavailable"><p>Reusable Google Cloud access is not enabled for this organization right now. Existing projects remain unchanged; no native fallback was created.</p><div className="connector-actions"><button type="button" disabled={loading} onClick={() => void refresh()}>{loading ? "Checking access…" : "Check again"}</button></div></ConnectorEmptyState>
    {loading && <ConnectorLoadingState label="Checking Google Cloud availability" compact />}
  </section>;
  return <section className="panel shared-aws-pilot" aria-label="Shared Google Cloud onboarding">
    <div className="shared-aws-pilot-heading"><div><h3>{items.length ? "Choose Google Cloud access" : "Grant Google Cloud access"}</h3><p>Reuse an approved project plan, or review keyless setup for another exact set of projects.</p></div><button type="button" disabled={busy || loading || statusLoading} onClick={() => { void refresh(); void readStatus(); }}>Check status</button></div>
    {listError && <ConnectorErrorState message={`${listError}. No fallback connection was created.`} onRetry={() => void refresh()} retrying={loading} />}
    {loading && <ConnectorLoadingState label="Refreshing Google Cloud access" compact />}
    {selected && <div className="shared-aws-pilot-detail">
      <label className="connector-field">Authorized connection<select value={selected.id} disabled={busy || loading || !!connection} onChange={(event) => { setSelectedId(event.target.value); setStatus(null); setStatusError(""); setError(""); setMessage(""); }}>{items.map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.availability}</option>)}</select></label>
      <p>{selected.projects.map((project) => `${project.id} (${project.number})`).join(" · ")}</p>
      {checkingStatus ? <ConnectorLoadingState label="Checking Google Cloud setup status" compact /> : status && <p role="status">{status.setup_state} · {status?.job_state ?? "idle"} · {status.health_state}</p>}
      {statusError && <ConnectorErrorState message={statusError} onRetry={() => void readStatus()} retrying={statusLoading} />}
      {canWrite && <div className="shared-aws-pilot-actions connector-actions">
        <button disabled={blocked || status?.setup_state !== "ready"} onClick={download}>Download setup script</button>
        <button disabled={blocked || !sharedGcpCanRetry(status, selected.availability)} onClick={() => void perform(async (current) => { await api.validateSharedGcp(selected.id); if (!current()) return; onProgress?.("verify"); await readStatus(); })}>{status?.setup_state === "ready" ? "Verify project access" : "Retry provisioning"}</button>
        <button disabled={blocked || selected.availability !== "ready"} onClick={() => void perform(async (current) => { const attached = await api.useSharedGcp(selected.id, connection?.declared_scopes ?? selected.validated_scopes); if (!current()) return; await onChanged(); if (!current()) return; await onAttached?.(attached); if (current()) setMessage("Attached in Denali. Validate and collect from its connection detail; collection uses durable jobs."); })}>Use in Denali</button>
      </div>}
      {canWrite && <details className="connection-organization-access"><summary>Organization-wide access</summary><p>These actions affect every application using these Google Cloud projects.</p><div className="shared-aws-pilot-actions">
        <button disabled={blocked || selected.availability === "disabled"} onClick={() => { if (window.confirm("Disable this shared Google Cloud connection for all authorized apps? Customer IAM bindings remain until removed separately.")) void perform(async (current) => { await api.disableSharedGcp(selected.id); if (current()) await refresh(); }); }}>Disable access for all applications</button>
        {selected.availability === "disabled" && <button className="danger-action" disabled={blocked} onClick={() => {
          const confirmation = window.prompt(`Type “${selected.display_name}” to delete this disabled shared plan for every app. Google IAM bindings, existing Denali references and collected evidence remain; remove them separately.`);
          if (confirmation === null) return;
          void perform(async (current) => {
            if (confirmation !== selected.display_name) throw new Error("Shared connection name confirmation failed");
            await api.deleteSharedGcp(selected.id, confirmation); if (!current()) return;
            await refresh(); if (!mounted.current) return; setStatus(null);
            setMessage("Shared plan deleted. Any Denali reference must be disabled and deleted separately; Google IAM grants and existing evidence were not removed.");
          });
        }}>Delete disabled shared plan</button>}
      </div></details>}
    </div>}
    {connection && !selected && !loading && !listError && <ConnectorEmptyState title="The original Google Cloud connection is unavailable">Its saved project and evidence selection has not been changed.</ConnectorEmptyState>}
    {!items.length && !loading && !listError && !connection && <ConnectorEmptyState title="No reusable Google Cloud access yet">Register the exact projects below, then review the keyless setup script before granting access.</ConnectorEmptyState>}
    {canWrite && !connection && !listError && <div className="connector-access-options">
      {items.length > 0 && <button className="connector-access-expander" type="button" aria-expanded={showCreate} disabled={busy || loading} onClick={() => setShowCreate(!showCreate)}>{showCreate ? "Cancel new Google Cloud setup" : "Set up new Google Cloud access"}</button>}
      {(!items.length || showCreate) && <form className="shared-aws-pilot-form connector-form" onSubmit={create}>
        <label className="connector-field">Name<input required disabled={busy || loading} maxLength={100} pattern="[A-Za-z0-9 _.()-]+" value={name} onChange={(event) => setName(event.target.value)} /></label>
        <label className="connector-field connector-field-wide">Projects (maximum 8)<textarea required disabled={busy || loading} value={projectText} placeholder={"my-project:123456789012\nother-project:234567890123"} onChange={(event) => setProjectText(event.target.value)} /><small className="connector-field-hint">One project ID and immutable project number per line.</small></label>
        <EvidenceScopePicker scopes={SCOPES} selected={scopes} onChange={setScopes} disabled={busy || loading} help="Choose the evidence this new project plan may read. No service-account JSON key is needed." />
        <div className="connector-actions"><button className="primary-action" disabled={busy || loading || !scopes.length}>Register shared Google Cloud</button></div>
      </form>}
    </div>}
    {busy && <ConnectorLoadingState label="Updating Google Cloud access" detail="Your request is in progress. Keyless provisioning and validation continue on the server when accepted." compact />}
    {message && <p role="status">{message}</p>}{error && <ConnectorErrorState message={`${error}. Shared failures never create a native fallback connection.`} />}
  </section>;
}
