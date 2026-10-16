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
import { ConnectorEmptyState, ConnectorErrorState, ConnectorLoadingState, EvidenceScopePicker } from "./ConnectorUi";

export function SharedGoogleWorkspacePilot({ canWrite, onChanged, connection, onAttached, onProgress }: SharedConnectionAdapterProps) {
  const [enabled, setEnabled] = useState(false);
  const [targets, setTargets] = useState<SharedGoogleWorkspaceTarget[]>([]);
  const [items, setItems] = useState<SharedGoogleWorkspaceConnection[]>([]);
  const [targetId, setTargetId] = useState("");
  const [selectedId, setSelectedId] = useState(() => platformConnectionId(connection));
  const [status, setStatus] = useState<SharedGoogleWorkspaceStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [statusLoading, setStatusLoading] = useState(false);
  const [operation, setOperation] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const creation = useRef<{ definition: string; id: string } | null>(null);
  const mounted = useRef(true);
  const generation = useRef(0);
  const actionGeneration = useRef(0);
  const actionPending = useRef(false);
  const selectedTarget = targets.find((target) => target.target_id === targetId) ?? targets[0];
  const selected = selectedId ? items.find((item) => item.id === selectedId) : items[0];
  const currentSource = useRef(selected?.id);
  const currentAttachment = useRef(connection?.id);
  currentSource.current = selected?.id;
  currentAttachment.current = connection?.id;
  const matchingStatus = selected && status && sharedGoogleWorkspaceSameBinding(selected, status) ? status : null;
  const validating = ["queued", "running"].includes(matchingStatus?.job_state ?? "");

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; generation.current += 1; actionGeneration.current += 1; }; }, []);

  const refresh = useCallback(async () => {
    const ticket = ++generation.current;
    setLoading(true);
    try {
    const [config, inventory] = await Promise.allSettled([
      api.sharedGoogleWorkspaceConfig(), api.sharedGoogleWorkspaceInventory(),
    ]);
    if (!mounted.current || ticket !== generation.current) return;
    const failures = [config, inventory].filter((result) => result.status === "rejected");
    const failure = failures.find((result) => !sharedGoogleWorkspaceNotEnabled(result.reason));
    if (failure) {
      setEnabled(true);
      setTargets([]); setItems([]); setStatus(null);
      setError(failure.reason instanceof Error ? failure.reason.message : "Shared Google Workspace is unavailable");
      return;
    }
    if (failures.length) { setEnabled(false); setTargets([]); setItems([]); setStatus(null); setError(""); return; }
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
    } finally { if (mounted.current && ticket === generation.current) setLoading(false); }
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
    if (!selected) { setStatusLoading(false); return; }
    let cancelled = false;
    setStatusLoading(true);
    void readStatus(selected.id).then((result) => {
      if (!cancelled) { setStatus(result); setError(""); }
    }).catch((cause) => {
      if (!cancelled) setError(cause instanceof Error ? cause.message : "Shared Google Workspace status is unavailable");
    }).finally(() => { if (!cancelled) setStatusLoading(false); });
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

  async function perform(task: (current: (createdSource?: string) => boolean) => Promise<void>, label: string) {
    if (actionPending.current || !canWrite || loading) return;
    actionPending.current = true;
    const ticket = ++actionGeneration.current;
    const source = currentSource.current;
    const attachment = currentAttachment.current;
    let created: string | undefined;
    const current = (createdSource?: string) => {
      if (createdSource !== undefined) created = createdSource;
      return mounted.current && ticket === actionGeneration.current && currentAttachment.current === attachment && (currentSource.current === source || (created !== undefined && currentSource.current === created));
    };
    setOperation(label);
    setBusy(true); setError(""); setMessage("");
    try { await task(current); }
    catch (cause) { if (current()) setError(cause instanceof Error ? cause.message : "Shared Google Workspace request failed"); }
    finally { if (ticket === actionGeneration.current) { actionPending.current = false; if (mounted.current) setBusy(false); } }
  }

  function create(event: FormEvent) {
    event.preventDefault();
    if (!canWrite || !selectedTarget) return;
    void perform(async (current) => {
      const definition = sharedGoogleWorkspaceRequestDefinition(selectedTarget.target_id);
      if (creation.current?.definition !== definition) creation.current = { definition, id: crypto.randomUUID() };
      const result = await api.startSharedGoogleWorkspaceSetup({
        target_id: selectedTarget.target_id,
        request_id: creation.current.id,
        declared_scopes: [...SHARED_GOOGLE_WORKSPACE_SCOPES],
      });
      if (!current()) return;
      await refresh();
      if (!current(result.id)) return;
      setSelectedId(result.id);
      const resultStatus = await readStatus(result.id);
      if (!current(result.id)) return;
      setStatus(resultStatus);
      setMessage("Plan recorded. Authorize the exact client and scope in Google Admin Console, then verify access here.");
    }, "Preparing the approved Workspace connection…");
  }

  const createForm = canWrite && !connection && (!selectedId || selected) && targets.length > 0 && !error && <form className="shared-aws-pilot-form connector-form" onSubmit={create}>
    <label className="connector-field"><span>Approved Workspace target</span><select value={selectedTarget?.target_id ?? ""} disabled={busy} onChange={(event) => setTargetId(event.target.value)}>{targets.map((target) => <option key={target.target_id} value={target.target_id}>{target.domain} · customer {target.customer_id}</option>)}</select></label>
    {selectedTarget && <p className="connector-field-hint">Delegated administrator: {selectedTarget.admin_email}. The fixed audit scope covers both Gemini and OAuth application activity.</p>}
    <div className="connector-actions"><button className="primary-action" disabled={busy || !selectedTarget}>Prepare shared Workspace connection</button></div>
  </form>;
  return <section className="panel shared-aws-pilot" aria-label="Shared Google Workspace onboarding">
    <div className="shared-aws-pilot-heading"><div><h3>Review Google Workspace access</h3><p>Use an authorized customer for read-only Gemini and OAuth application audit activity.</p></div><button type="button" disabled={busy || loading} onClick={() => void refresh()}>Check status</button></div>
    {loading ? <ConnectorLoadingState label="Loading approved Workspace access…" detail="Checking authorized customers and their fixed audit scope before showing setup controls." /> : <>
    {!enabled && !error && <ConnectorEmptyState title="Reusable Workspace access is unavailable"><p>Check organization access or contact an administrator. Existing Denali configuration is preserved.</p><button type="button" onClick={() => void refresh()}>Check organization access</button></ConnectorEmptyState>}
    {enabled && selectedId && !selected && !error && <ConnectorErrorState message="The original Workspace connection is unavailable. Existing Denali configuration and evidence remain preserved." onRetry={() => void refresh()} />}
    {enabled && selected && <div className="shared-aws-pilot-detail connector-form">
      <label className="connector-field"><span>Authorized connection</span><select value={selected.id} disabled={busy || !!connection} onChange={(event) => { setSelectedId(event.target.value); setStatus(null); }}>{items.map((item) => <option key={item.id} value={item.id}>{item.domain} · customer {item.customer_id}</option>)}</select></label>
      <p className="connector-field-hint">Customer {selected.customer_id} · domain {selected.domain} · delegated administrator {selected.admin_email}</p>
      {connection?.lifecycle_state === "disabled" && <p className="connector-field-hint">This Denali attachment is disabled. Reviewing Workspace access does not reactivate it.</p>}
      {statusLoading && <ConnectorLoadingState compact label="Checking current Workspace access…" detail="Both audit planes must be verified for this exact customer." />}
      <EvidenceScopePicker label="Workspace audit evidence" scopes={SHARED_GOOGLE_WORKSPACE_SCOPES} selected={SHARED_GOOGLE_WORKSPACE_SCOPES} onChange={() => {}} disabled help="This fixed read-only bundle always includes both audit planes. No additional scope is requested." />
      <details className="connector-access-expander" open={selected.setup_state !== "ready"}>
      <summary>Review Google Admin authorization</summary>
      <div className="connection-setup-card workspace-authorization-card">
        <div className="connection-setup-card-head"><span>Authorization</span><div><strong>Authorize these exact values in Google Admin Console</strong><small>A Workspace super administrator opens API controls → Domain-wide delegation and adds the OAuth client ID with the sole scope below.</small></div></div>
        <div className="workspace-copy-item"><strong>Platform service account</strong><code>{selected.service_account}</code></div>
        <div className="workspace-copy-item"><strong>Numeric OAuth client ID</strong><code>{selected.oauth_client_id}</code></div>
        <div className="workspace-copy-item"><strong>OAuth scope</strong><code>{GOOGLE_WORKSPACE_AUDIT_SCOPE}</code></div>
        {canWrite && <div className="connector-actions"><a className="primary-action" href={GOOGLE_WORKSPACE_ADMIN_CONSOLE_URL} target="_blank" rel="noreferrer">Open Google Admin Console</a></div>}
        <p>After authorizing this customer, return and verify access. Propagation can take several minutes. Both audit planes must pass validation before this connection can be used in Denali.</p>
      </div>
      </details>
      <p role="status">{matchingStatus?.setup_state ?? "checking access"} · {matchingStatus?.job_state ?? "idle"} · {matchingStatus?.health_state ?? "unknown"}</p>
      {matchingStatus?.validation_results && <div className="validation-grid">{matchingStatus.validation_results.map((result) => <div key={result.scope} className={result.state}><div><strong>{result.scope === "google_workspace.gemini_activity" ? "Gemini in Workspace activity" : "OAuth application activity"}</strong><small>{result.state === "passed" ? "Read access verified" : "Read access failed"}</small></div></div>)}</div>}
      {matchingStatus?.error_code && <p role="alert">Workspace validation failed ({matchingStatus.error_code}). Review the exact customer and domain-wide delegation values, then retry.</p>}
      {status && !matchingStatus && <p role="alert">The Workspace binding changed. Refresh and review the approved customer before continuing.</p>}
      {canWrite && <div className="connector-actions">
        <button disabled={busy || statusLoading || validating || selected.lifecycle_state !== "active"} onClick={() => void perform(async (current) => {
          setStatus(null);
          onProgress?.("verify", "Verifying both Workspace audit planes");
          if (!current()) return;
          const result = await api.validateSharedGoogleWorkspace(selected.id);
          if (!current()) return;
          if (result.id !== selected.id) throw new Error("Workspace validation returned a different connection");
          const validatedItems = sharedGoogleWorkspaceAcceptValidation(items, selected, result);
          setItems(validatedItems);
          setStatus(result);
          setMessage(sharedGoogleWorkspaceCanAttach(result)
            ? "Both Workspace audit planes passed validation. You can now use this connection in Denali."
            : "Workspace verification returned its access results. Review any failed planes before retrying.");
        }, "Verifying both Workspace audit planes…")}>{validating ? "Verifying Workspace access…" : "I authorized it — verify access"}</button>
        <button disabled={busy || statusLoading || !sharedGoogleWorkspaceCanAttach(matchingStatus) || !!error} onClick={() => void perform(async (isCurrent) => {
          const current = await api.sharedGoogleWorkspaceStatus(selected.id);
          if (!isCurrent()) return;
          if (!sharedGoogleWorkspaceSameBinding(selected, current) || !sharedGoogleWorkspaceCanAttach(current)) {
            setStatus(current);
            throw new Error("Both Workspace audit planes must be validated for this exact customer before attachment");
          }
          const attached = await api.useSharedGoogleWorkspaceInDenali(selected.id);
          if (!isCurrent()) return;
          await onChanged(); if (!isCurrent()) return;
          await onAttached?.(attached);
          if (isCurrent()) setMessage("Attached in Denali. Open its connection detail to validate and collect Workspace evidence using durable jobs.");
        }, "Attaching the verified Workspace customer…")}>Use in Denali</button>
      </div>}
    </div>}
    {enabled && !selected && !selectedId && !error && <ConnectorEmptyState title={targets.length ? "No authorized Workspace connections" : "No approved Workspace targets"}><p>{targets.length ? "Prepare an approved customer, then authorize its exact read-only audit scope." : "An administrator must admit a Workspace customer before a new connection can be prepared."}</p></ConnectorEmptyState>}
    {enabled && createForm && (items.length > 0 ? <details className="connector-access-expander"><summary>Prepare another approved Workspace connection</summary>{createForm}</details> : createForm)}
    {message && <p role="status">{message}</p>}{error && <ConnectorErrorState message={error} onRetry={() => void refresh()} />}
    </>}
    {busy && !loading && <ConnectorLoadingState compact label={operation} detail="Your request is in progress. The exact customer and fixed read-only bundle stay unchanged." />}
  </section>;
}
