import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, type SharedAzureReposConnection, type SharedAzureReposTarget } from "./api";
import type { ConnectionRepositoryBoundary } from "./types";
import { platformConnectionId, type SharedConnectionAdapterProps } from "./sharedConnectionAdapter";
import { useSharedStatusPolling } from "./useSharedStatusPolling";
import { ConnectorEmptyState, ConnectorErrorState, ConnectorLoadingState, EvidenceScopePicker } from "./ConnectorUi";
import { ConnectorRepositoryPicker } from "./ConnectorRepositoryPicker";

const SCOPES = ["azure_repos.repository_metadata", "azure_repos.repository_contents"];
function sameRepository(left: ConnectionRepositoryBoundary, right: ConnectionRepositoryBoundary) {
  return left.id === right.id && left.project_id === right.project_id
    && left.name.toLowerCase() === right.name.toLowerCase()
    && left.project_name?.toLowerCase() === right.project_name?.toLowerCase();
}

export function SharedAzureReposPilot({ canWrite, onChanged, connection, onAttached, onProgress, platformId }: SharedConnectionAdapterProps & { platformId?: string }) {
  const [items, setItems] = useState<SharedAzureReposConnection[]>([]);
  const [targets, setTargets] = useState<SharedAzureReposTarget[]>([]);
  const [targetId, setTargetId] = useState("");
  const [selectedId, setSelectedId] = useState(() => platformConnectionId(connection) || platformId || "");
  const [repositories, setRepositories] = useState<ConnectionRepositoryBoundary[]>([]);
  const [repositoryIds, setRepositoryIds] = useState<string[]>([]);
  const [scopes, setScopes] = useState(SCOPES);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingRepositories, setLoadingRepositories] = useState(false);
  const [repositorySource, setRepositorySource] = useState("");
  const [checkingStatus, setCheckingStatus] = useState(false);
  const [checkedSource, setCheckedSource] = useState("");
  const [operation, setOperation] = useState("");
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const creation = useRef<{ definition: string; request: string } | null>(null);
  const launch = useRef<{ source: string; request: string } | null>(null);
  const choices = useRef<{ source: string; repositories: ConnectionRepositoryBoundary[]; ids: string[] } | null>(null);
  const selected = selectedId ? items.find((item) => item.id === selectedId) : items[0];
  const target = targets.find((item) => item.target_id === targetId) ?? targets[0];
  const mounted = useRef(true);
  const generation = useRef(0);
  const statusGeneration = useRef(0);
  const actionGeneration = useRef(0);
  const actionPending = useRef(false);
  const currentSource = useRef(selected?.id);
  const currentAttachment = useRef(connection?.id);
  currentSource.current = selected?.id;
  currentAttachment.current = connection?.id;
  const sourceKey = selected ? JSON.stringify([selected.id, selected.setup_state, selected.last_validated_at, selected.authority_revision, selected.repository_count]) : "";
  const repositoriesPending = Boolean(!error && selected?.setup_state === "ready" && (loadingRepositories || repositorySource !== sourceKey));
  const statusPending = checkingStatus || Boolean(!error && selected && checkedSource !== selected.id);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; generation.current += 1; actionGeneration.current += 1; }; }, []);
  const refresh = useCallback(async () => {
    const ticket = ++generation.current;
    setLoading(true);
    try {
      const [config, listing] = await Promise.all([api.sharedAzureReposConfig(), api.sharedAzureReposConnections()]);
      if (!mounted.current || ticket !== generation.current) return;
      setTargets(config.items); setItems(listing.items); setUnavailable(false); setError("");
    } catch (cause) {
      if (mounted.current && ticket === generation.current) {
        if (cause instanceof Error && "status" in cause && cause.status === 404) { setUnavailable(true); setTargets([]); setItems([]); setError(""); }
        else setError(cause instanceof Error ? cause.message : "Azure Repos access is unavailable");
      }
    } finally { if (mounted.current && ticket === generation.current) setLoading(false); }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    const onReturn = () => { if (document.visibilityState !== "hidden") void refresh(); };
    window.addEventListener("focus", onReturn);
    document.addEventListener("visibilitychange", onReturn);
    return () => { window.removeEventListener("focus", onReturn); document.removeEventListener("visibilitychange", onReturn); };
  }, [refresh]);
  const readStatus = useSharedStatusPolling({
    identity: selected?.id,
    read: async (id) => {
      const ticket = ++statusGeneration.current;
      setCheckingStatus(true);
      try {
        const result = await api.sharedAzureReposStatus(id);
        if (result.id !== id) throw new Error("Azure Repos status does not match the selected connection");
        return result;
      } finally { if (mounted.current && ticket === statusGeneration.current) setCheckingStatus(false); }
    },
    pending: (result) => ["queued", "running"].includes(result.job_state ?? ""),
    accept: (result) => {
      setItems((previous) => previous.map((item) => item.id === result.id ? result : item));
      setCheckedSource(result.id);
      onProgress?.(result.setup_state === "ready" ? "verify" : "grant");
    },
    reject: (cause) => setError(cause instanceof Error ? cause.message : "Azure Repos status is unavailable"),
  });
  useEffect(() => {
    if (!selected || selected.setup_state !== "ready") { setRepositories([]); setRepositoryIds([]); setLoadingRepositories(false); return; }
    let cancelled = false;
    setLoadingRepositories(true);
    void api.sharedAzureReposRepositories(selected.id).then((result) => {
      if (cancelled) return;
      const previous = choices.current?.source === selected.id ? choices.current : null;
      const saved = platformConnectionId(connection) === selected.id ? connection?.configuration.repositories ?? [] : [];
      const before = previous?.repositories ?? saved;
      const ids = (previous?.ids ?? saved.map((repo) => String(repo.id))).filter((id) => {
        const old = before.find((repo) => String(repo.id) === id);
        const current = result.items.find((repo) => repo.id === id);
        return old && current && sameRepository(old, current);
      });
      choices.current = { source: selected.id, repositories: result.items, ids };
      setRepositories(result.items); setRepositoryIds(ids); setRepositorySource(sourceKey);
    }).catch((cause) => { if (!cancelled) { setRepositories([]); setRepositoryIds([]); setError(cause instanceof Error ? cause.message : "The verified repository list is unavailable"); } })
      .finally(() => { if (!cancelled) setLoadingRepositories(false); });
    return () => { cancelled = true; };
  }, [selected?.id, selected?.setup_state, selected?.last_validated_at, selected?.authority_revision, selected?.repository_count]);
  async function perform(action: (current: (createdSource?: string) => boolean) => Promise<void>, label: string) {
    if (actionPending.current || !canWrite || loading || unavailable) return;
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
    try { await action(current); }
    catch (cause) { if (current()) setError(cause instanceof Error ? cause.message : "Azure Repos request failed"); }
    finally { if (ticket === actionGeneration.current) { actionPending.current = false; if (mounted.current) setBusy(false); } }
  }
  function create(event: FormEvent) {
    event.preventDefault();
    if (!target) return;
    void perform(async (current) => {
      const definition = JSON.stringify([target.target_id, [...scopes].sort()]);
      if (creation.current?.definition !== definition) creation.current = { definition, request: crypto.randomUUID() };
      const result = await api.createSharedAzureRepos({ target_id: target.target_id, request_id: creation.current.request, declared_scopes: [...scopes].sort() });
      if (!current()) return;
      await refresh(); if (!current(result.id)) return; setSelectedId(result.id);
      setMessage("Connection plan recorded. Authorize Microsoft access to verify the exact organization and repository candidates.");
    }, "Preparing the approved Azure Repos plan…");
  }
  function prepare() {
    if (!selected) return;
    void perform(async (current) => {
      if (launch.current?.source !== selected.id) launch.current = { source: selected.id, request: crypto.randomUUID() };
      const result = await api.startSharedAzureReposSetup(selected.id, { request_id: launch.current.request, ...(connection ? { connection_id: connection.id } : {}) });
      if (!current()) return;
      const url = new URL(result.authorize_url);
      if (url.protocol !== "https:" || url.host !== "login.microsoftonline.com" || url.pathname !== `/${selected.tenant_id}/oauth2/v2.0/authorize` || url.username || url.password || url.hash) throw new Error("Microsoft authorization link is invalid");
      window.location.assign(url.href);
    }, "Preparing Microsoft authorization…");
  }
  const createForm = canWrite && !connection && (!selectedId || selected) && targets.length > 0 && !error && <form className="shared-aws-pilot-form connector-form" onSubmit={create}>
    <label className="connector-field"><span>Approved Azure DevOps organization</span><select value={target?.target_id ?? ""} disabled={busy} onChange={(event) => setTargetId(event.target.value)}>{targets.map((item) => <option key={item.target_id} value={item.target_id}>{item.display_name} · {item.organization}</option>)}</select></label>
    <EvidenceScopePicker scopes={SCOPES} selected={scopes} requiredScopes={[SCOPES[0]]} disabled={busy} onChange={(next) => setScopes(next.includes(SCOPES[1]) ? SCOPES : [SCOPES[0]])} help="Metadata is required. Repository source analysis is optional and stays explicitly selected." />
    <p className="connector-field-hint">A customer administrator must separately grant this application read access to the selected organization.</p>
    <div className="connector-actions"><button className="primary-action" disabled={busy}>Prepare Azure Repos connection</button></div>
  </form>;
  return <section className="panel shared-aws-pilot" aria-label="Azure Repos access and repository selection">
    <div className="shared-aws-pilot-heading"><div><h3>Review Azure Repos access</h3><p>Use an authorized organization, then select the exact repositories Denali may analyze.</p></div><button type="button" disabled={busy || loading} onClick={() => { void refresh(); void readStatus(); }}>Check status</button></div>
    {loading ? <ConnectorLoadingState label="Loading approved Azure DevOps organizations…" detail="Checking authorized sources before showing setup controls." /> : unavailable ? <ConnectorEmptyState title="Reusable Azure Repos access is unavailable"><p>Check organization access or contact an administrator. Existing Denali connections remain unchanged.</p><button type="button" onClick={() => void refresh()}>Check organization access</button></ConnectorEmptyState> : <>
    {selectedId && !selected && !error && <ConnectorErrorState message="The original Azure Repos plan is unavailable. Existing Denali evidence remains preserved." onRetry={() => void refresh()} />}
    {selected && <div className="shared-aws-pilot-detail connector-form"><label className="connector-field"><span>Azure DevOps connection</span><select value={selected.id} disabled={busy || !!connection} onChange={(event) => setSelectedId(event.target.value)}>{items.map((item) => <option key={item.id} value={item.id}>{item.organization} · {item.availability}</option>)}</select></label>
      <p>Microsoft tenant {selected.tenant_id} · organization {selected.organization}</p><p role="status">{selected.setup_state} · {selected.job_state ?? "idle"} · {selected.health_state}</p>
      {connection?.lifecycle_state === "disabled" && <p className="connector-field-hint">This Denali attachment is disabled. Reviewing repository access does not reactivate it.</p>}
      {statusPending && <ConnectorLoadingState compact label="Checking current Azure Repos access…" />}
      {canWrite && <div className="connector-actions"><button type="button" disabled={busy || statusPending || selected.setup_state !== "ready" || ["queued", "running"].includes(selected.job_state ?? "")} onClick={() => void perform(async (current) => { await api.validateSharedAzureRepos(selected.id); if (!current()) return; onProgress?.("verify"); if (current()) await readStatus(); }, "Verifying Azure Repos application access…")}>Verify application access</button></div>}
      <p><strong>Available:</strong> {repositoriesPending ? "Checking verified repositories…" : `${repositories.length} verified repositories`} · <strong>Saved in this Denali connection:</strong> {connection?.configuration.repositories?.length ?? 0} · <strong>In this review:</strong> {repositoryIds.length}.</p>
      {repositoriesPending ? <ConnectorLoadingState compact label="Checking verified repository identities…" detail="Matching saved choices are retained; new repositories remain unchecked." /> : repositories.length > 0 && <ConnectorRepositoryPicker label="Select exact repositories for Denali" items={repositories.map((repo) => ({ id: String(repo.id), name: repo.full_name, detail: repo.project_name }))} selected={repositoryIds} disabled={!canWrite || busy} onChange={(ids) => {
        setRepositoryIds(ids); choices.current = { source: selected.id, repositories, ids };
      }} />}
      {!repositoriesPending && selected.setup_state === "ready" && repositories.length === 0 && !error && <ConnectorEmptyState title="No verified repositories available"><p>Review Microsoft authorization before selecting repositories.</p></ConnectorEmptyState>}
      {connection && <p>Saving a changed repository selection creates a separate attachment. The existing connection and evidence remain until you explicitly disconnect it.</p>}
      {canWrite && <div className="connector-actions"><button className="primary-action" type="button" disabled={busy || statusPending || repositoriesPending || !!error || selected.availability !== "ready" || repositoryIds.length === 0} onClick={() => void perform(async (current) => { const attached = await api.useSharedAzureRepos(selected.id, repositoryIds, connection?.declared_scopes ?? selected.declared_scopes); if (!current()) return; await onChanged(); if (current()) await onAttached?.(attached); }, "Attaching the reviewed Azure repositories…")}>Use selected repositories in Denali</button></div>}
      {canWrite && <details className="connector-access-expander" open={selected.setup_state !== "ready"}><summary>Review Microsoft authorization</summary><p className="connector-field-hint">Authorize this exact organization again to synchronize repository access. Denali selections stay unchanged until you save.</p><div className="connector-actions"><button type="button" disabled={busy || selected.lifecycle_state !== "active"} onClick={prepare}>Review Microsoft authorization</button></div></details>}
      {canWrite && <details className="connection-organization-access"><summary>Organization-wide access</summary><p>These actions affect all applications using this Azure Repos connection. Azure DevOps grants and Denali evidence remain.</p><button disabled={busy || selected.lifecycle_state !== "active"} onClick={() => { if (window.confirm("Disable this Azure Repos connection for all consuming applications?")) void perform(async (current) => { await api.disableSharedAzureRepos(selected.id); if (!current()) return; await refresh(); if (current()) await onChanged(); }, "Updating organization-wide Azure Repos access…"); }}>Disable access for all applications</button>{selected.lifecycle_state === "disabled" && <button className="danger-action" disabled={busy} onClick={() => {
        const confirmation = window.prompt(`Type “${selected.display_name}” to delete the disabled shared plan. Existing Denali references and evidence remain.`);
        if (confirmation === selected.display_name) void perform(async (current) => { await api.deleteSharedAzureRepos(selected.id, confirmation); if (current()) await refresh(); }, "Deleting the disabled organization plan…");
      }}>Delete disabled organization plan</button>}</details>}
    </div>}
    {!selected && !selectedId && !error && <ConnectorEmptyState title={targets.length ? "No authorized Azure Repos connections" : "No approved Azure DevOps targets"}><p>{targets.length ? "Prepare an approved organization to review its exact repositories." : "An administrator must admit an organization before a new connection can be prepared."}</p></ConnectorEmptyState>}
    {createForm && (items.length > 0 ? <details className="connector-access-expander"><summary>Prepare another approved Azure Repos connection</summary>{createForm}</details> : createForm)}
    {message && <p role="status">{message}</p>}{error && <ConnectorErrorState message={error} onRetry={() => { void refresh(); void readStatus(); }} />}
    </>}
    {busy && !loading && <ConnectorLoadingState compact label={operation} detail="Your request is in progress. The exact organization and saved selections stay unchanged." />}
  </section>;
}
