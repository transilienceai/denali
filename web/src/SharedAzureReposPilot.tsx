import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, type SharedAzureReposConnection, type SharedAzureReposTarget } from "./api";
import type { ConnectionRepositoryBoundary } from "./types";
import { platformConnectionId, type SharedConnectionAdapterProps } from "./sharedConnectionAdapter";
import { useSharedStatusPolling } from "./useSharedStatusPolling";

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
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const creation = useRef<{ definition: string; request: string } | null>(null);
  const launch = useRef<{ source: string; request: string } | null>(null);
  const choices = useRef<{ source: string; repositories: ConnectionRepositoryBoundary[]; ids: string[] } | null>(null);
  const selected = selectedId ? items.find((item) => item.id === selectedId) : items[0];
  const target = targets.find((item) => item.target_id === targetId) ?? targets[0];
  const mounted = useRef(true);
  const generation = useRef(0);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const refresh = useCallback(async () => {
    const ticket = ++generation.current;
    try {
      const [config, listing] = await Promise.all([api.sharedAzureReposConfig(), api.sharedAzureReposConnections()]);
      if (!mounted.current || ticket !== generation.current) return;
      setTargets(config.items); setItems(listing.items); setError("");
    } catch (cause) {
      if (mounted.current && ticket === generation.current) setError(cause instanceof Error ? cause.message : "Azure Repos access is unavailable");
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
    read: (id) => api.sharedAzureReposStatus(id),
    pending: (result) => ["queued", "running"].includes(result.job_state ?? ""),
    accept: (result) => {
      setItems((previous) => previous.map((item) => item.id === result.id ? result : item));
      onProgress?.(result.setup_state === "ready" ? "verify" : "grant");
    },
    reject: (cause) => setError(cause instanceof Error ? cause.message : "Azure Repos status is unavailable"),
  });
  useEffect(() => {
    if (!selected || selected.setup_state !== "ready") { setRepositories([]); setRepositoryIds([]); return; }
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
      setRepositories(result.items); setRepositoryIds(ids);
    }).catch((cause) => { if (!cancelled) { setRepositories([]); setRepositoryIds([]); setError(cause instanceof Error ? cause.message : "The verified repository list is unavailable"); } })
      .finally(() => { if (!cancelled) setLoadingRepositories(false); });
    return () => { cancelled = true; };
  }, [selected?.id, selected?.setup_state, selected?.last_validated_at, selected?.authority_revision]);
  async function perform(action: () => Promise<void>) {
    if (busy || !canWrite) return;
    setBusy(true); setError(""); setMessage("");
    try { await action(); }
    catch (cause) { if (mounted.current) setError(cause instanceof Error ? cause.message : "Azure Repos request failed"); }
    finally { if (mounted.current) setBusy(false); }
  }
  function create(event: FormEvent) {
    event.preventDefault();
    if (!target) return;
    void perform(async () => {
      const definition = JSON.stringify([target.target_id, [...scopes].sort()]);
      if (creation.current?.definition !== definition) creation.current = { definition, request: crypto.randomUUID() };
      const result = await api.createSharedAzureRepos({ target_id: target.target_id, request_id: creation.current.request, declared_scopes: [...scopes].sort() });
      await refresh(); setSelectedId(result.id);
      setMessage("Connection plan recorded. Authorize Microsoft access to verify the exact organization and repository candidates.");
    });
  }
  function prepare() {
    if (!selected) return;
    void perform(async () => {
      if (launch.current?.source !== selected.id) launch.current = { source: selected.id, request: crypto.randomUUID() };
      const result = await api.startSharedAzureReposSetup(selected.id, { request_id: launch.current.request, ...(connection ? { connection_id: connection.id } : {}) });
      const url = new URL(result.authorize_url);
      if (url.protocol !== "https:" || url.host !== "login.microsoftonline.com" || url.pathname !== `/${selected.tenant_id}/oauth2/v2.0/authorize` || url.username || url.password || url.hash) throw new Error("Microsoft authorization link is invalid");
      window.location.assign(url.href);
    });
  }
  return <section className="panel shared-aws-pilot" aria-label="Azure Repos access and repository selection">
    <div className="shared-aws-pilot-heading"><div><h3>Grant Azure Repos access</h3><p>Verify the approved Microsoft tenant and Azure DevOps organization, then explicitly select repositories for Denali. Platform retains the provider credentials.</p></div><button disabled={busy || loading} onClick={() => { void refresh(); void readStatus(); }}>Check status</button></div>
    {loading && <p role="status">Loading approved Azure DevOps organizations…</p>}
    {canWrite && !connection && targets.length > 0 && <form className="shared-aws-pilot-form" onSubmit={create}><label>Approved Azure DevOps organization<select value={target?.target_id ?? ""} onChange={(event) => setTargetId(event.target.value)}>{targets.map((item) => <option key={item.target_id} value={item.target_id}>{item.display_name} · {item.organization}</option>)}</select></label><fieldset><legend>Read-only evidence</legend><label className="shared-github-repository-choice"><input type="checkbox" checked disabled />Repository metadata (required)</label><label className="shared-github-repository-choice"><input type="checkbox" checked={scopes.includes(SCOPES[1])} onChange={(event) => setScopes(event.target.checked ? SCOPES : [SCOPES[0]])} />Repository source analysis</label></fieldset><p>A customer administrator must separately grant this application read access to the selected organization.</p><button className="primary-action" disabled={busy}>Prepare Azure Repos connection</button></form>}
    {!loading && targets.length === 0 && !error && <p>No approved Azure DevOps target is configured for this organization.</p>}
    {!loading && selectedId && !selected && !error && <p role="alert">The original Azure Repos plan is unavailable. Existing Denali evidence remains preserved.</p>}
    {selected && <div className="shared-aws-pilot-detail"><label>Azure DevOps connection<select value={selected.id} disabled={busy || !!connection} onChange={(event) => setSelectedId(event.target.value)}>{items.map((item) => <option key={item.id} value={item.id}>{item.organization} · {item.availability}</option>)}</select></label>
      <p>Microsoft tenant {selected.tenant_id} · organization {selected.organization}</p><p role="status">{selected.setup_state} · {selected.job_state ?? "idle"} · {selected.health_state}</p>
      {canWrite && <div className="shared-aws-pilot-actions"><button disabled={busy || selected.lifecycle_state !== "active"} onClick={prepare}>Review Microsoft authorization</button><button disabled={busy || selected.setup_state !== "ready" || ["queued", "running"].includes(selected.job_state ?? "")} onClick={() => void perform(async () => { await api.validateSharedAzureRepos(selected.id); onProgress?.("verify"); await readStatus(); })}>Verify application access</button></div>}
      <p><strong>Available:</strong> {repositories.length} verified repositories · <strong>Saved in this Denali connection:</strong> {connection?.configuration.repositories?.length ?? 0} · <strong>In this review:</strong> {repositoryIds.length}.</p>
      {loadingRepositories ? <p role="status">Checking verified repository identities…</p> : repositories.length > 0 && <fieldset><legend>Select exact repositories for Denali</legend>{repositories.map((repo) => <label className="shared-github-repository-choice" key={String(repo.id)}><input type="checkbox" checked={repositoryIds.includes(String(repo.id))} disabled={!canWrite || busy} onChange={(event) => {
        const ids = event.target.checked ? [...repositoryIds, String(repo.id)] : repositoryIds.filter((id) => id !== String(repo.id));
        setRepositoryIds(ids); choices.current = { source: selected.id, repositories, ids };
      }} />{repo.full_name}</label>)}</fieldset>}
      {connection && <p>Saving a changed repository selection creates a separate attachment. The existing connection and evidence remain until you explicitly disconnect it.</p>}
      {canWrite && <button className="primary-action" disabled={busy || loadingRepositories || !!error || selected.availability !== "ready" || repositoryIds.length === 0} onClick={() => void perform(async () => { const attached = await api.useSharedAzureRepos(selected.id, repositoryIds, connection?.declared_scopes ?? selected.declared_scopes); await onChanged(); await onAttached?.(attached); })}>Use selected repositories in Denali</button>}
      {canWrite && <details className="connection-organization-access"><summary>Organization-wide access</summary><p>These actions affect all applications using this Azure Repos connection. Azure DevOps grants and Denali evidence remain.</p><button disabled={busy || selected.lifecycle_state !== "active"} onClick={() => { if (window.confirm("Disable this Azure Repos connection for all consuming applications?")) void perform(async () => { await api.disableSharedAzureRepos(selected.id); await refresh(); await onChanged(); }); }}>Disable access for all applications</button>{selected.lifecycle_state === "disabled" && <button className="danger-action" disabled={busy} onClick={() => {
        const confirmation = window.prompt(`Type “${selected.display_name}” to delete the disabled shared plan. Existing Denali references and evidence remain.`);
        if (confirmation === selected.display_name) void perform(async () => { await api.deleteSharedAzureRepos(selected.id, confirmation); await refresh(); });
      }}>Delete disabled organization plan</button>}</details>}
    </div>}
    {message && <p role="status">{message}</p>}{error && <p role="alert">{error}</p>}
  </section>;
}
