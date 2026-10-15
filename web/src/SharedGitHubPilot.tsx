import { useCallback, useEffect, useRef, useState } from "react";
import { api, type SharedGitHubConnection, type SharedGitHubRepository } from "./api";
import { platformConnectionId, type SharedConnectionAdapterProps } from "./sharedConnectionAdapter";
import {
  githubRepositoryChanges, retainGithubRepositorySelection, selectedGithubRepositoryIds,
  sharedGithubNotEnabled, verifiedInstallUrl,
} from "./sharedGithubOnboarding";

export function SharedGitHubPilot({ canWrite, onChanged, connection, onAttached, onProgress, workflowId }: SharedConnectionAdapterProps & { workflowId?: string }) {
  const [available, setAvailable] = useState(false);
  const [items, setItems] = useState<SharedGitHubConnection[]>([]);
  const [selectedId, setSelectedId] = useState(() => platformConnectionId(connection));
  const [repositories, setRepositories] = useState<SharedGitHubRepository[]>([]);
  const [repositoryIds, setRepositoryIds] = useState<number[]>([]);
  const [scopes, setScopes] = useState<string[]>([]);
  const scopeSource = useRef<string | null>(null);
  const [installUrl, setInstallUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [loadingRepositories, setLoadingRepositories] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const requestId = useRef<string | null>(null);
  const listingGeneration = useRef(0);
  const mounted = useRef(true);
  const selection = useRef<{ id: string; repositories: SharedGitHubRepository[]; ids: number[] } | null>(null);
  const selected = selectedId ? items.find((item) => item.id === selectedId) : items[0];
  const savedRepositories = connection?.configuration.repositories ?? [];
  const changes = githubRepositoryChanges(savedRepositories, repositories);

  useEffect(() => {
    if (!selected) return;
    if (scopeSource.current !== selected.id) {
      scopeSource.current = selected.id;
      setScopes(connection?.declared_scopes ?? [...selected.validated_scopes]);
    } else {
      // Freshly granted scopes never widen an existing review automatically.
      setScopes((previous) => previous.filter((scope) => selected.validated_scopes.includes(scope)));
    }
  }, [selected, connection?.id]);

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const refresh = useCallback(async () => {
    const generation = ++listingGeneration.current;
    try {
      const result = await api.sharedGithubConnections();
      if (!mounted.current || generation !== listingGeneration.current) return;
      setItems(result.items.filter((item) => item.connection_kind === "shared_github"));
      setAvailable(true); setError("");
    } catch (cause) {
      if (!mounted.current || generation !== listingGeneration.current) return;
      if (sharedGithubNotEnabled(cause)) { setAvailable(false); return; }
      setAvailable(true);
      setError(cause instanceof Error ? cause.message : "GitHub access is temporarily unavailable");
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    const onReturn = () => { if (document.visibilityState !== "hidden") void refresh(); };
    window.addEventListener("focus", onReturn);
    document.addEventListener("visibilitychange", onReturn);
    return () => { window.removeEventListener("focus", onReturn); document.removeEventListener("visibilitychange", onReturn); };
  }, [refresh]);
  useEffect(() => {
    if (!workflowId) return;
    let cancelled = false;
    void api.onboardingWorkflow(workflowId).then((workflow) => {
      if (cancelled) return;
      if (workflow.platform_connection_id) setSelectedId(workflow.platform_connection_id);
      setMessage(workflow.error_code ? "GitHub setup did not complete. Review access and retry."
        : "You returned from GitHub. Review the verified available repositories before saving Denali’s selection.");
      onProgress?.("verify", "Review the repositories included in Denali");
    }).catch((cause) => { if (!cancelled) setError(cause instanceof Error ? cause.message : "Setup could not be resumed in this organization"); });
    return () => { cancelled = true; };
  }, [workflowId]);
  useEffect(() => {
    if (!selected || selected.availability !== "ready") {
      setRepositories([]); setRepositoryIds([]); setLoadingRepositories(false);
      return;
    }
    let cancelled = false;
    setLoadingRepositories(true);
    void api.sharedGithubRepositories(selected.id).then((result) => {
      if (cancelled) return;
      const previous = selection.current?.id === selected.id ? selection.current : null;
      const saved = platformConnectionId(connection) === selected.id ? connection?.configuration.repositories ?? [] : [];
      const ids = retainGithubRepositorySelection(previous?.ids ?? saved.map((repo) => Number(repo.id)), previous?.repositories ?? saved, result.items);
      selection.current = { id: selected.id, repositories: result.items, ids };
      setRepositories(result.items); setRepositoryIds(ids);
    }).catch((cause) => {
      if (!cancelled) { setRepositories([]); setRepositoryIds([]); setError(cause instanceof Error ? cause.message : "The verified repository list is unavailable"); }
    }).finally(() => { if (!cancelled) setLoadingRepositories(false); });
    return () => { cancelled = true; };
  // A refresh can change repository identities without changing ID or count.
  }, [selected]);

  async function perform(task: () => Promise<void>) {
    if (busy || !canWrite) return;
    setBusy(true); setMessage(""); setError("");
    try { await task(); }
    catch (cause) { if (mounted.current) setError(cause instanceof Error ? cause.message : "GitHub request failed"); }
    finally { if (mounted.current) setBusy(false); }
  }

  function startSetup() {
    void perform(async () => {
      requestId.current ??= crypto.randomUUID();
      const result = await api.startSharedGithubSetup({ request_id: requestId.current,
        ...(connection ? { connection_id: connection.id } : {}),
        ...(selected ? { platform_connection_id: selected.id } : {}),
      });
      const url = verifiedInstallUrl(result.install_url);
      setInstallUrl(url);
      onProgress?.("grant", "Review GitHub access and complete authorization");
      setMessage("Complete GitHub authorization to synchronize repository access. You will return here to review Denali’s selected repositories.");
      window.location.assign(url);
    });
  }

  function useInDenali() {
    if (!selected) return;
    void perform(async () => {
      const ids = selectedGithubRepositoryIds(repositoryIds, repositories.map((repo) => repo.id));
      const attached = await api.useSharedGithubInDenali(selected.id, ids, scopes);
      await onChanged(); await onAttached?.(attached);
      setMessage("Repository selection saved. Verify access and collect evidence from the connection detail.");
    });
  }

  function disable() {
    if (!selected || !window.confirm("Disable this GitHub connection for all Transilience applications in this organization? Existing short-lived tokens expire separately. Disconnect from Denali in its connection detail to affect only Denali.")) return;
    void perform(async () => { await api.disableSharedGithub(selected.id); await refresh(); await onChanged(); });
  }

  if (!available) return null;
  return <section className="panel shared-aws-pilot" aria-label="GitHub access and repository selection">
    <div className="shared-aws-pilot-heading"><div><h3>Review GitHub access</h3><p>GitHub access and Denali’s analysis selection are separate. Reauthorize to synchronize changes made in GitHub settings, then approve the repositories Denali should analyze.</p></div><button type="button" disabled={busy || loadingRepositories} onClick={() => void refresh()}>Reload saved access</button></div>
    {canWrite && <div className="shared-aws-pilot-actions"><button type="button" disabled={busy} onClick={startSetup}>Manage repository access in GitHub</button>{installUrl && <a href={installUrl} rel="noopener noreferrer">Continue GitHub authorization ↗</a>}</div>}
    {selectedId && !selected && !error && <p role="alert">The original GitHub installation is unavailable. Review its organization access before continuing.</p>}
    {items.length === 0 && !error && <p>Authorize GitHub to discover the repositories available to this organization.</p>}
    {selected && <div className="shared-aws-pilot-detail">
      <label>GitHub account<select value={selected.id} disabled={busy || !!connection} onChange={(event) => { requestId.current = null; setSelectedId(event.target.value); }}>{items.map((item) => <option key={item.id} value={item.id}>{item.account_login} · {item.repository_count} available · {item.availability}</option>)}</select></label>
      <div className="connection-repository-summary"><p><strong>Available through Platform:</strong> {selected.repository_count} repositories. Saved GitHub access: {selected.repository_selection === "all" ? "all repositories" : "selected repositories"}.</p><p><strong>Selected for this Denali connection:</strong> {connection ? savedRepositories.length : 0} saved · {repositoryIds.length} in this review.</p><p>Last verified by Platform: {selected.last_validated_at ? new Date(selected.last_validated_at).toLocaleString() : "Not recorded"}. Reloading saved access does not synchronize changes made directly in GitHub.</p></div>
      {connection && !loadingRepositories && <div className="connection-repository-changes" role="status">
        <p>{changes.added.length} available beyond the saved selection · {changes.removed.length} no longer available · {changes.changed.length} changed identity.</p>
        {changes.removed.length > 0 && <p>Unavailable: {changes.removed.map((repo) => repo.full_name).join(", ")}</p>}
        {changes.changed.length > 0 && <p>Identity changed; these repositories require a new explicit selection: {changes.changed.map((repo) => repo.full_name).join(", ")}</p>}
        <p>Saving a different selection creates a replacement attachment. The existing connection and its evidence remain until you separately disconnect it from Denali.</p>
        {connection.lifecycle_state === "disabled" && <p>This Denali attachment is disabled. Reviewing GitHub access does not reactivate it.</p>}
      </div>}
      {loadingRepositories && <p role="status">Checking the verified repository list…</p>}
      {!loadingRepositories && repositories.length > 0 && <fieldset><legend>Select repositories for Denali analysis</legend><ul>{repositories.map((repo) => <li key={repo.id}><label className="shared-github-repository-choice"><input type="checkbox" disabled={!canWrite || busy} checked={repositoryIds.includes(repo.id)} onChange={(event) => {
        const ids = event.target.checked ? [...repositoryIds, repo.id] : repositoryIds.filter((id) => id !== repo.id);
        setRepositoryIds(ids); selection.current = { id: selected.id, repositories, ids };
      }} />{repo.full_name}{changes.added.some((added) => added.id === repo.id) && connection ? " · available to add" : ""}{repo.archived ? " · archived" : ""}</label></li>)}</ul><p>Existing choices survive refresh while their identities match. Newly available repositories remain unchecked until you choose them.</p></fieldset>}
      <fieldset aria-label="GitHub evidence selection"><legend>Read-only evidence for the reviewed attachment</legend>{selected.validated_scopes.map((scope) => <label className="shared-github-repository-choice" key={scope}><input type="checkbox" checked={scopes.includes(scope)} disabled={!canWrite || busy} onChange={(event) => setScopes(event.target.checked ? [...scopes, scope] : scopes.filter((item) => item !== scope))} />{scope === "github.repository_metadata" ? "Repository metadata" : scope === "github.repository_contents" ? "Repository source analysis" : "GitHub Actions metadata"}</label>)}<p>Only checked evidence planes are saved. Changing this selection creates a replacement attachment; it never expands the original connection.</p></fieldset>
      {canWrite && <button className="primary-action" type="button" disabled={busy || loadingRepositories || selected.availability !== "ready" || repositoryIds.length === 0 || scopes.length === 0} onClick={useInDenali}>{connection ? "Save reviewed repository selection" : "Use selected repositories in Denali"}</button>}
      {canWrite && <details className="connection-organization-access"><summary>Organization-wide access</summary><p>Disabling here stops new GitHub access for every consuming application, while collected Denali evidence remains.</p><button type="button" disabled={busy || selected.availability === "disabled"} onClick={disable}>Disable access for all applications</button></details>}
    </div>}
    {message && <p className="shared-aws-pilot-message" role="status">{message}</p>}{error && <p className="shared-aws-pilot-error" role="alert">{error}</p>}
  </section>;
}
