import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, type SharedGoogleWorkspaceConnection, type SharedGoogleWorkspaceStatus, type SharedGoogleWorkspaceTarget } from "./api";
import {
  GOOGLE_WORKSPACE_ADMIN_CONSOLE_URL,
  GOOGLE_WORKSPACE_AUDIT_SCOPE,
  SHARED_GOOGLE_WORKSPACE_SCOPES,
  sharedGoogleWorkspaceAcceptValidation,
  sharedGoogleWorkspaceCanAttach,
  sharedGoogleWorkspaceHasFixedScopes,
  sharedGoogleWorkspaceNotEnabled,
  sharedGoogleWorkspaceRequestDefinition,
  sharedGoogleWorkspaceSameBinding,
} from "./sharedGoogleWorkspaceOnboarding";
import { platformConnectionId, type SharedConnectionAdapterProps } from "./sharedConnectionAdapter";

export function SharedGoogleWorkspacePilot({ canWrite, onChanged, connection, onAttached, onProgress }: SharedConnectionAdapterProps) {
  const [enabled, setEnabled] = useState(false);
  const [targets, setTargets] = useState<SharedGoogleWorkspaceTarget[]>([]);
  const [items, setItems] = useState<SharedGoogleWorkspaceConnection[]>([]);
  const [targetId, setTargetId] = useState("");
  const [selectedId, setSelectedId] = useState(() => platformConnectionId(connection));
  const [status, setStatus] = useState<SharedGoogleWorkspaceStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const creation = useRef<{ definition: string; id: string } | null>(null);
  const selectedTarget = targets.find((target) => target.target_id === targetId) ?? targets[0];
  const selected = selectedId ? items.find((item) => item.id === selectedId) : items[0];
  const matchingStatus = selected && status && sharedGoogleWorkspaceSameBinding(selected, status) ? status : null;
  const validating = ["queued", "running"].includes(matchingStatus?.job_state ?? "");

  const refresh = useCallback(async () => {
    const [config, inventory] = await Promise.allSettled([
      api.sharedGoogleWorkspaceConfig(), api.sharedGoogleWorkspaceInventory(),
    ]);
    const failures = [config, inventory].filter((result) => result.status === "rejected");
    const failure = failures.find((result) => !sharedGoogleWorkspaceNotEnabled(result.reason));
    if (failure) {
      setEnabled(true);
      setTargets([]); setItems([]); setStatus(null);
      setError(failure.reason instanceof Error ? failure.reason.message : "Shared Google Workspace is unavailable");
      return;
    }
    if (failures.length) { setEnabled(false); setTargets([]); setItems([]); setStatus(null); return; }
    if (config.status === "fulfilled" && inventory.status === "fulfilled") {
      if (!config.value.enabled || !sharedGoogleWorkspaceHasFixedScopes(config.value.declared_scopes) ||
        config.value.authorization_scope !== GOOGLE_WORKSPACE_AUDIT_SCOPE ||
        config.value.setup_method !== "domain_wide_delegation") {
        setTargets([]); setItems([]); setStatus(null); setEnabled(true);
        setError("Shared Workspace configuration does not match the fixed read-only audit bundle");
        return;
      }
      setTargets(config.value.items);
      setItems(inventory.value.items);
      setEnabled(true);
      setError("");
    }
  }, []);

  const readStatus = useCallback(async (id: string) => {
    const result = await api.sharedGoogleWorkspaceStatus(id);
    if (result.id !== id) throw new Error("Google Workspace status does not match the selected connection");
    return result;
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    const onReturn = () => { if (document.visibilityState !== "hidden") void refresh(); };
    window.addEventListener("focus", onReturn);
    document.addEventListener("visibilitychange", onReturn);
    return () => { window.removeEventListener("focus", onReturn); document.removeEventListener("visibilitychange", onReturn); };
  }, [refresh]);
  useEffect(() => {
    setStatus(null);
    if (!selected) return;
    let cancelled = false;
    void readStatus(selected.id).then((result) => {
      if (!cancelled) { setStatus(result); setError(""); }
    }).catch((cause) => {
      if (!cancelled) setError(cause instanceof Error ? cause.message : "Shared Google Workspace status is unavailable");
    });
    return () => { cancelled = true; };
  }, [selected, readStatus]);
  useEffect(() => {
    if (!selected || !validating) return;
    let cancelled = false;
    let pending = false;
    const timer = window.setInterval(() => {
      if (pending) return;
      pending = true;
      void readStatus(selected.id).then((result) => {
        if (!cancelled) { setStatus(result); setError(""); }
      }).catch((cause) => {
        if (!cancelled) {
          setStatus(null);
          setError(cause instanceof Error ? cause.message : "Workspace validation status is unavailable");
        }
      }).finally(() => { pending = false; });
    }, 3000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [selected, validating, readStatus]);

  async function perform(task: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(""); setMessage("");
    try { await task(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Shared Google Workspace request failed"); }
    finally { setBusy(false); }
  }

  function create(event: FormEvent) {
    event.preventDefault();
    if (!canWrite || !selectedTarget) return;
    void perform(async () => {
      const definition = sharedGoogleWorkspaceRequestDefinition(selectedTarget.target_id);
      if (creation.current?.definition !== definition) creation.current = { definition, id: crypto.randomUUID() };
      const result = await api.startSharedGoogleWorkspaceSetup({
        target_id: selectedTarget.target_id,
        request_id: creation.current.id,
        declared_scopes: [...SHARED_GOOGLE_WORKSPACE_SCOPES],
      });
      await refresh();
      setSelectedId(result.id);
      setStatus(await readStatus(result.id));
      setMessage("Plan recorded. Authorize the exact client and scope in Google Admin Console, then verify access here.");
    });
  }

  if (!enabled) return null;
  return <section className="panel shared-aws-pilot" aria-label="Shared Google Workspace onboarding">
    <div className="shared-aws-pilot-heading"><div><h3>Grant Google Workspace access</h3><p>Choose the approved Workspace customer for read-only Gemini and OAuth application audit activity.</p></div><button type="button" disabled={busy} onClick={() => void refresh()}>Check status</button></div>
    {canWrite && !connection && targets.length > 0 && <form className="shared-aws-pilot-form" onSubmit={create}>
      <label>Approved Workspace target<select value={selectedTarget?.target_id ?? ""} disabled={busy} onChange={(event) => setTargetId(event.target.value)}>{targets.map((target) => <option key={target.target_id} value={target.target_id}>{target.domain} · customer {target.customer_id}</option>)}</select></label>
      {selectedTarget && <p>Delegated administrator: {selectedTarget.admin_email}. Both Gemini in Workspace activity and OAuth application activity use the fixed read-only audit scope.</p>}
      <button className="primary-action" disabled={busy || !selectedTarget}>Prepare shared Workspace connection</button>
    </form>}
    {targets.length === 0 && !error && <p>No approved Workspace targets are configured for this organization.</p>}
    {selected && <div className="shared-aws-pilot-detail">
      <label>Authorized connection<select value={selected.id} disabled={busy || !!connection} onChange={(event) => { setSelectedId(event.target.value); setStatus(null); }}>{items.map((item) => <option key={item.id} value={item.id}>{item.domain} · customer {item.customer_id}</option>)}</select></label>
      <p>Customer {selected.customer_id} · domain {selected.domain} · delegated administrator {selected.admin_email}</p>
      <div className="connection-setup-card workspace-authorization-card">
        <div className="connection-setup-card-head"><span>Authorization</span><div><strong>Authorize these exact values in Google Admin Console</strong><small>A Workspace super administrator opens API controls → Domain-wide delegation and adds the OAuth client ID with the sole scope below.</small></div></div>
        <div className="workspace-copy-item"><strong>Platform service account</strong><code>{selected.service_account}</code></div>
        <div className="workspace-copy-item"><strong>Numeric OAuth client ID</strong><code>{selected.oauth_client_id}</code></div>
        <div className="workspace-copy-item"><strong>OAuth scope</strong><code>{GOOGLE_WORKSPACE_AUDIT_SCOPE}</code></div>
        <div className="connection-launch-actions"><a className="primary-action" href={GOOGLE_WORKSPACE_ADMIN_CONSOLE_URL} target="_blank" rel="noreferrer">Open Google Admin Console</a></div>
        <p>After authorizing this customer, return and verify access. Propagation can take several minutes. Both audit planes must pass validation before this connection can be used in Denali.</p>
      </div>
      <p role="status">{matchingStatus?.setup_state ?? "checking access"} · {matchingStatus?.job_state ?? "idle"} · {matchingStatus?.health_state ?? "unknown"}</p>
      {matchingStatus?.validation_results && <div className="validation-grid">{matchingStatus.validation_results.map((result) => <div key={result.scope} className={result.state}><div><strong>{result.scope === "google_workspace.gemini_activity" ? "Gemini in Workspace activity" : "OAuth application activity"}</strong><small>{result.state === "passed" ? "Read access verified" : "Read access failed"}</small></div></div>)}</div>}
      {matchingStatus?.error_code && <p role="alert">Workspace validation failed ({matchingStatus.error_code}). Review the exact customer and domain-wide delegation values, then retry.</p>}
      {status && !matchingStatus && <p role="alert">The Workspace binding changed. Refresh and review the approved customer before continuing.</p>}
      {canWrite && <div className="shared-aws-pilot-actions">
        <button disabled={busy || validating || selected.lifecycle_state !== "active"} onClick={() => void perform(async () => {
          setStatus(null);
          onProgress?.("verify", "Verifying both Workspace audit planes");
          const result = await api.validateSharedGoogleWorkspace(selected.id);
          if (result.id !== selected.id) throw new Error("Workspace validation returned a different connection");
          const validatedItems = sharedGoogleWorkspaceAcceptValidation(items, selected, result);
          setItems(validatedItems);
          setStatus(result);
          setMessage(sharedGoogleWorkspaceCanAttach(result)
            ? "Both Workspace audit planes passed validation. You can now use this connection in Denali."
            : "Workspace verification returned its access results. Review any failed planes before retrying.");
        })}>{validating ? "Verifying Workspace access…" : "I authorized it — verify access"}</button>
        <button disabled={busy || !sharedGoogleWorkspaceCanAttach(matchingStatus) || !!error} onClick={() => void perform(async () => {
          const current = await api.sharedGoogleWorkspaceStatus(selected.id);
          if (!sharedGoogleWorkspaceSameBinding(selected, current) || !sharedGoogleWorkspaceCanAttach(current)) {
            setStatus(current);
            throw new Error("Both Workspace audit planes must be validated for this exact customer before attachment");
          }
          const attached = await api.useSharedGoogleWorkspaceInDenali(selected.id);
          await onChanged();
          await onAttached?.(attached);
          setMessage("Attached in Denali. Open its connection detail to validate and collect Workspace evidence using durable jobs.");
        })}>Use in Denali</button>
      </div>}
    </div>}
    {message && <p role="status">{message}</p>}{error && <p role="alert">{error}</p>}
  </section>;
}
