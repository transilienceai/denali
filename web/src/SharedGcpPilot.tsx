import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, type SharedGcpConnection, type SharedGcpStatus } from "./api";
import { parseSharedGcpProjects, sharedGcpCanRetry, sharedGcpNotEnabled } from "./sharedGcpOnboarding";
import { platformConnectionId, type SharedConnectionAdapterProps } from "./sharedConnectionAdapter";
import { useSharedStatusPolling } from "./useSharedStatusPolling";

const SCOPES = ["gcp.vertex_ai", "gcp.agent_builder", "gcp.code_to_cloud", "gcp.ai_activity"];

export function SharedGcpPilot({ canWrite, onChanged, connection, onAttached, onProgress }: SharedConnectionAdapterProps) {
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
  const creation = useRef<{ definition: string; id: string } | null>(null);
  const selected = selectedId ? items.find((item) => item.id === selectedId) : items[0];

  const refresh = useCallback(async () => {
    try {
      const result = await api.sharedGcpConnections();
      setItems(result.items);
      setEnabled(true);
      setError("");
    } catch (cause) {
      if (sharedGcpNotEnabled(cause)) { setEnabled(false); return; }
      setEnabled(true);
      setError(cause instanceof Error ? cause.message : "Shared Google Cloud is unavailable");
    }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);
  const readStatus = useSharedStatusPolling({
    identity: selected?.id,
    read: (id) => api.sharedGcpStatus(id),
    pending: (result) => ["queued", "running"].includes(result.job_state ?? ""),
    accept: (result) => {
      setStatus(result);
      onProgress?.(result.setup_state === "ready" ? "verify" : "grant");
      if (result.job_state === "succeeded" || result.job_state === "failed") void refresh();
    },
    reject: (cause) => { setStatus(null); setError(cause instanceof Error ? cause.message : "Google Cloud status is unavailable"); },
  });
  useEffect(() => { setStatus(null); }, [selected?.id]);

  async function perform(task: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try { await task(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Shared Google Cloud request failed"); }
    finally { setBusy(false); }
  }
  function create(event: FormEvent) {
    event.preventDefault();
    void perform(async () => {
      const projects = parseSharedGcpProjects(projectText);
      const declaredScopes = [...scopes].sort();
      const definition = JSON.stringify({ display_name: name.trim(), projects, declared_scopes: declaredScopes });
      if (creation.current?.definition !== definition) creation.current = { definition, id: crypto.randomUUID() };
      const result = await api.createSharedGcp({ request_id: creation.current.id, display_name: name.trim(), projects, declared_scopes: declaredScopes });
      await refresh(); setSelectedId(result.id);
      setMessage("Keyless principal provisioning queued. Review and apply its exact project setup script when ready, then validate.");
    });
  }
  function download() {
    if (!selected) return;
    void perform(async () => {
      const blob = await api.sharedGcpScript(selected.id);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = `transilience-gcp-${selected.id}.sh`; anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setMessage("Inspect the script before running it in Google Cloud Shell as an administrator of these exact projects. No service-account JSON key is needed.");
    });
  }
  if (!enabled) return null;
  return <section className="panel shared-aws-pilot" aria-label="Shared Google Cloud onboarding">
    <div className="shared-aws-pilot-heading"><div><h3>Grant Google Cloud access</h3><p>Choose the exact projects and read-only evidence to connect. Review the generated keyless setup script before granting access.</p></div><button type="button" disabled={busy} onClick={() => { void refresh(); void readStatus(); }}>Check status</button></div>
    {canWrite && !connection && <form className="shared-aws-pilot-form" onSubmit={create}>
      <label>Name<input required maxLength={100} pattern="[A-Za-z0-9 _.()-]+" value={name} onChange={(event) => setName(event.target.value)} /></label>
      <label>Projects (maximum 8)<textarea required value={projectText} placeholder={"my-project:123456789012\nother-project:234567890123"} onChange={(event) => setProjectText(event.target.value)} /></label>
      <fieldset><legend>Read-only evidence planes</legend>{SCOPES.map((scope) => <label key={scope}><input type="checkbox" checked={scopes.includes(scope)} onChange={(event) => setScopes(event.target.checked ? [...scopes, scope] : scopes.filter((item) => item !== scope))} />{scope.replace("gcp.", "").replaceAll("_", " ")}</label>)}</fieldset>
      <button className="primary-action" disabled={busy || !scopes.length}>Register shared Google Cloud</button>
    </form>}
    {selected && <div className="shared-aws-pilot-detail">
      <label>Authorized connection<select value={selected.id} disabled={busy || !!connection} onChange={(event) => { setSelectedId(event.target.value); setStatus(null); }}>{items.map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.availability}</option>)}</select></label>
      <p>{selected.projects.map((project) => `${project.id} (${project.number})`).join(" · ")}</p>
      <p role="status">{status?.setup_state ?? "checking"} · {status?.job_state ?? "idle"} · {status?.health_state ?? "unknown"}</p>
      {canWrite && <div className="shared-aws-pilot-actions">
        <button disabled={busy || status?.setup_state !== "ready"} onClick={download}>Download setup script</button>
        <button disabled={busy || !sharedGcpCanRetry(status, selected.availability)} onClick={() => void perform(async () => { await api.validateSharedGcp(selected.id); onProgress?.("verify"); await readStatus(); })}>{status?.setup_state === "ready" ? "Verify project access" : "Retry provisioning"}</button>
        <button disabled={busy || selected.availability !== "ready"} onClick={() => void perform(async () => { const attached = await api.useSharedGcp(selected.id, connection?.declared_scopes ?? selected.validated_scopes); await onChanged(); await onAttached?.(attached); setMessage("Attached in Denali. Validate and collect from its connection detail; collection uses durable jobs."); })}>Use in Denali</button>
      </div>}
      {canWrite && <details className="connection-organization-access"><summary>Organization-wide access</summary><p>These actions affect every application using these Google Cloud projects.</p><div className="shared-aws-pilot-actions">
        <button disabled={busy || selected.availability === "disabled"} onClick={() => { if (window.confirm("Disable this shared Google Cloud connection for all authorized apps? Customer IAM bindings remain until removed separately.")) void perform(async () => { await api.disableSharedGcp(selected.id); await refresh(); }); }}>Disable access for all applications</button>
        {selected.availability === "disabled" && <button className="danger-action" disabled={busy} onClick={() => {
          const confirmation = window.prompt(`Type “${selected.display_name}” to delete this disabled shared plan for every app. Google IAM bindings, existing Denali references and collected evidence remain; remove them separately.`);
          if (confirmation === null) return;
          void perform(async () => {
            if (confirmation !== selected.display_name) throw new Error("Shared connection name confirmation failed");
            await api.deleteSharedGcp(selected.id, confirmation); await refresh(); setStatus(null);
            setMessage("Shared plan deleted. Any Denali reference must be disabled and deleted separately; Google IAM grants and existing evidence were not removed.");
          });
        }}>Delete disabled shared plan</button>}
      </div></details>}
    </div>}
    {message && <p role="status">{message}</p>}{error && <p role="alert">{error}. Shared failures never create a native fallback connection.</p>}
  </section>;
}
