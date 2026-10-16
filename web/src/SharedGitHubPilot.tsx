import { useCallback, useEffect, useRef, useState } from "react";
import { api, type SharedGitHubConnection, type SharedGitHubRepository } from "./api";
import { platformConnectionId, type SharedConnectionAdapterProps } from "./sharedConnectionAdapter";
import { ConnectorEmptyState, ConnectorErrorState, ConnectorLoadingState, EvidenceScopePicker } from "./ConnectorUi";
import { ConnectorRepositoryPicker } from "./ConnectorRepositoryPicker";
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
  const [loading, setLoading] = useState(true);
  const [loadingRepositories, setLoadingRepositories] = useState(false);
  const [repositorySource, setRepositorySource] = useState<SharedGitHubConnection | null>(null);
  const [workflowLoading, setWorkflowLoading] = useState(Boolean(workflowId));
  const [workflowError, setWorkflowError] = useState("");
  const [workflowRetry, setWorkflowRetry] = useState(0);
  const [operation, setOperation] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const requestId = useRef<string | null>(null);
  const listingGeneration = useRef(0);
  const mounted = useRef(true);
  const actionGeneration = useRef(0);
  const actionPending = useRef(false);
  const selection = useRef<{ id: string; repositories: SharedGitHubRepository[]; ids: number[] } | null>(null);
  const selected = selectedId ? items.find((item) => item.id === selectedId) : items[0];
  const currentSource = useRef(selected?.id);
  const currentAttachment = useRef(connection?.id);
  currentSource.current = selected?.id;
  currentAttachment.current = connection?.id;
  const savedRepositories = connection?.configuration.repositories ?? [];
  const changes = githubRepositoryChanges(savedRepositories, repositories);
  const repositoriesPending = Boolean(!error && selected?.availability === "ready" && (loadingRepositories || repositorySource !== selected));

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

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; listingGeneration.current += 1; actionGeneration.current += 1; }; }, []);
  const refresh = useCallback(async () => {
    const generation = ++listingGeneration.current;
    setLoading(true);
    try {
      const result = await api.sharedGithubConnections();
      if (!mounted.current || generation !== listingGeneration.current) return;
      setItems(result.items.filter((item) => item.connection_kind === "shared_github"));
      setAvailable(true); setError("");
    } catch (cause) {
      if (!mounted.current || generation !== listingGeneration.current) return;
      if (sharedGithubNotEnabled(cause)) { setAvailable(false); setItems([]); setError(""); return; }
      setAvailable(true);
      setError(cause instanceof Error ? cause.message : "GitHub access is temporarily unavailable");
    } finally {
      if (mounted.current && generation === listingGeneration.current) setLoading(false);
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
    if (!workflowId) { setWorkflowLoading(false); setWorkflowError(""); return; }
    let cancelled = false;
    setWorkflowLoading(true); setWorkflowError("");
    void api.onboardingWorkflow(workflowId).then((workflow) => {
      if (cancelled) return;
      if (workflow.platform_connection_id) setSelectedId(workflow.platform_connection_id);
      setMessage(workflow.error_code ? "GitHub setup did not complete. Review access and retry."
        : "You returned from GitHub. Review the verified available repositories before saving Denali’s selection.");
      onProgress?.("verify", "Review the repositories included in Denali");
    }).catch((cause) => { if (!cancelled) setWorkflowError(cause instanceof Error ? cause.message : "Setup could not be resumed in this organization"); })
      .finally(() => { if (!cancelled) setWorkflowLoading(false); });
    return () => { cancelled = true; };
  }, [workflowId, workflowRetry]);
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
      setRepositories(result.items); setRepositoryIds(ids); setRepositorySource(selected);
    }).catch((cause) => {
      if (!cancelled) { setRepositories([]); setRepositoryIds([]); setError(cause instanceof Error ? cause.message : "The verified repository list is unavailable"); }
    }).finally(() => { if (!cancelled) setLoadingRepositories(false); });
    return () => { cancelled = true; };
  // A refresh can change repository identities without changing ID or count.
  }, [selected]);

  async function perform(task: (current: () => boolean) => Promise<void>, label: string) {
    if (actionPending.current || !canWrite || loading || workflowLoading || workflowError) return;
    actionPending.current = true;
    const generation = ++actionGeneration.current;
    const source = currentSource.current;
    const attachment = currentAttachment.current;
    const current = () => mounted.current && generation === actionGeneration.current && currentSource.current === source && currentAttachment.current === attachment;
    setOperation(label);
    setBusy(true); setMessage(""); setError("");
    try { await task(current); }
    catch (cause) { if (current()) setError(cause instanceof Error ? cause.message : "GitHub request failed"); }
    finally { if (generation === actionGeneration.current) { actionPending.current = false; if (mounted.current) setBusy(false); } }
  }

  function startSetup() {
    void perform(async (current) => {
      requestId.current ??= crypto.randomUUID();
      const result = await api.startSharedGithubSetup({ request_id: requestId.current,
        ...(connection ? { connection_id: connection.id } : {}),
        ...(selected ? { platform_connection_id: selected.id } : {}),
      });
      if (!current()) return;
      const url = verifiedInstallUrl(result.install_url);
      setInstallUrl(url);
      onProgress?.("grant", "Review GitHub access and complete authorization");
      setMessage("Complete GitHub authorization to synchronize repository access. You will return here to review Denali’s selected repositories.");
      if (current()) window.location.assign(url);
    }, "Preparing GitHub authorization…");
  }

  function useInDenali() {
    if (!selected) return;
    void perform(async (current) => {
      const ids = selectedGithubRepositoryIds(repositoryIds, repositories.map((repo) => repo.id));
      const attached = await api.useSharedGithubInDenali(selected.id, ids, scopes);
      if (!current()) return;
      await onChanged(); if (!current()) return;
      await onAttached?.(attached);
      if (current()) setMessage("Repository selection saved. Verify access and collect evidence from the connection detail.");
    }, "Saving the reviewed repository selection…");
  }

  function disable() {
    if (!selected || !window.confirm("Disable this GitHub connection for all Transilience applications in this organization? Existing short-lived tokens expire separately. Disconnect from Denali in its connection detail to affect only Denali.")) return;
    void perform(async (current) => { await api.disableSharedGithub(selected.id); if (!current()) return; await refresh(); if (current()) await onChanged(); }, "Updating organization-wide GitHub access…");
  }

  return <section className="panel shared-aws-pilot" aria-label="GitHub access and repository selection">
    <div className="shared-aws-pilot-heading"><div><h3>Review GitHub access</h3><p>Review an authorized account and the exact repositories Denali may analyze.</p></div><button type="button" disabled={busy || loading || workflowLoading || repositoriesPending} onClick={() => void refresh()}>Reload saved access</button></div>
    {loading || workflowLoading ? <ConnectorLoadingState label={workflowLoading ? "Resuming your GitHub review…" : "Loading authorized GitHub accounts…"} detail="Existing connections and selected repositories stay unchanged." /> : workflowError ? <ConnectorErrorState message={workflowError} onRetry={() => setWorkflowRetry((retry) => retry + 1)} /> : <>
    {!available && !error && <ConnectorEmptyState title="Reusable GitHub access is unavailable"><p>Check organization access or contact an administrator. Existing Denali connections remain unchanged.</p><button type="button" onClick={() => void refresh()}>Check organization access</button></ConnectorEmptyState>}
    {available && selectedId && !selected && !error && <ConnectorErrorState message="The original GitHub installation is unavailable. Review its organization access before continuing." onRetry={() => void refresh()} />}
    {available && items.length === 0 && !selectedId && !error && <ConnectorEmptyState title="No authorized GitHub accounts"><p>Authorize GitHub to discover the repositories available to this organization.</p>{canWrite && <div className="connector-actions"><button type="button" disabled={busy} onClick={startSetup}>Manage repository access in GitHub</button></div>}</ConnectorEmptyState>}
    {available && selected && <div className="shared-aws-pilot-detail connector-form">
      <label className="connector-field"><span>GitHub account</span><select value={selected.id} disabled={busy || !!connection} onChange={(event) => { requestId.current = null; setSelectedId(event.target.value); }}>{items.map((item) => <option key={item.id} value={item.id}>{item.account_login} · {item.repository_count} available · {item.availability}</option>)}</select></label>
      <div className="connection-repository-summary"><p><strong>Available through Platform:</strong> {selected.repository_count} repositories. Saved GitHub access: {selected.repository_selection === "all" ? "all repositories" : "selected repositories"}.</p><p><strong>Selected for this Denali connection:</strong> {connection ? savedRepositories.length : 0} saved · {repositoryIds.length} in this review.</p><p>Last verified by Platform: {selected.last_validated_at ? new Date(selected.last_validated_at).toLocaleString() : "Not recorded"}. Reloading saved access does not synchronize changes made directly in GitHub.</p></div>
      {connection && !repositoriesPending && <div className="connection-repository-changes" role="status">
        <p>{changes.added.length} available beyond the saved selection · {changes.removed.length} no longer available · {changes.changed.length} changed identity.</p>
        {changes.removed.length > 0 && <p>Unavailable: {changes.removed.map((repo) => repo.full_name).join(", ")}</p>}
        {changes.changed.length > 0 && <p>Identity changed; these repositories require a new explicit selection: {changes.changed.map((repo) => repo.full_name).join(", ")}</p>}
        <p>Saving a different selection creates a replacement attachment. The existing connection and its evidence remain until you separately disconnect it from Denali.</p>
        {connection.lifecycle_state === "disabled" && <p>This Denali attachment is disabled. Reviewing GitHub access does not reactivate it.</p>}
      </div>}
      {repositoriesPending && <ConnectorLoadingState compact label="Checking the verified repository list…" detail="Matching saved identities remain selected. New repositories are never added automatically." />}
      {!repositoriesPending && repositories.length > 0 && <ConnectorRepositoryPicker items={repositories.map((repo) => ({ id: repo.id, name: repo.full_name,
        detail: [changes.added.some((added) => added.id === repo.id) && connection ? "Available to add" : "", repo.archived ? "Archived" : ""].filter(Boolean).join(" · "),
      }))} selected={repositoryIds} disabled={!canWrite || busy} onChange={(ids) => {
        setRepositoryIds(ids); selection.current = { id: selected.id, repositories, ids };
      }} />}
      {!repositoriesPending && selected.availability === "ready" && repositories.length === 0 && !error && <ConnectorEmptyState title="No verified repositories available"><p>Review GitHub authorization before choosing an analysis boundary.</p></ConnectorEmptyState>}
      <EvidenceScopePicker ariaLabel="GitHub evidence selection" label="Read-only evidence for the reviewed attachment" scopes={selected.validated_scopes} selected={scopes} onChange={setScopes} disabled={!canWrite || busy} help="Only checked evidence planes are saved. Changing this selection creates a replacement attachment; it never expands the original connection." />
      {canWrite && <div className="connector-actions"><button className="primary-action" type="button" disabled={busy || repositoriesPending || selected.availability !== "ready" || repositoryIds.length === 0 || scopes.length === 0 || !!error} onClick={useInDenali}>{connection ? "Save reviewed repository selection" : "Use selected repositories in Denali"}</button></div>}
      {canWrite && <details className="connector-access-expander"><summary>Review GitHub authorization</summary><p className="connector-field-hint">Reauthorize to synchronize changes made in GitHub settings. This never changes Denali’s saved selection.</p><div className="connector-actions"><button type="button" disabled={busy} onClick={startSetup}>Manage repository access in GitHub</button>{installUrl && <a href={installUrl} rel="noopener noreferrer">Continue GitHub authorization ↗</a>}</div></details>}
      {canWrite && <details className="connection-organization-access"><summary>Organization-wide access</summary><p>Disabling here stops new GitHub access for every consuming application, while collected Denali evidence remains.</p><button type="button" disabled={busy || selected.availability === "disabled"} onClick={disable}>Disable access for all applications</button></details>}
    </div>}
    {message && <p className="shared-aws-pilot-message" role="status">{message}</p>}{error && <ConnectorErrorState message={error} onRetry={() => void refresh()} />}
    </>}
    {busy && !loading && !workflowLoading && <ConnectorLoadingState compact label={operation} detail="Your request is in progress. Existing connections and evidence remain preserved." />}
  </section>;
}
