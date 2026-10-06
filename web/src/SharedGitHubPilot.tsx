import { useCallback, useEffect, useState } from "react";
import { api, type SharedGitHubConnection, type SharedGitHubRepository } from "./api";
import { selectedGithubRepositoryIds, sharedGithubNotEnabled, verifiedInstallUrl } from "./sharedGithubOnboarding";

export function SharedGitHubPilot({ canWrite, onChanged }: { canWrite: boolean; onChanged: () => Promise<void> }) {
  const [available, setAvailable] = useState(false);
  const [items, setItems] = useState<SharedGitHubConnection[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [repositories, setRepositories] = useState<SharedGitHubRepository[]>([]);
  const [repositoryIds, setRepositoryIds] = useState<number[]>([]);
  const [installUrl, setInstallUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const selected = items.find((item) => item.id === selectedId) ?? items[0];

  const refresh = useCallback(async () => {
    try {
      const result = await api.sharedGithubConnections();
      setItems(result.items.filter((item) => item.connection_kind === "shared_github"));
      setAvailable(true);
      setError("");
    } catch (cause) {
      if (sharedGithubNotEnabled(cause)) { setAvailable(false); return; }
      setAvailable(true);
      setError(cause instanceof Error ? cause.message : "Shared GitHub is unavailable; no native connection was created");
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    setRepositories([]);
    setRepositoryIds([]);
    if (!selected || selected.availability !== "ready") return;
    let current = true;
    void api.sharedGithubRepositories(selected.id).then((result) => {
      if (current) setRepositories(result.items);
    }).catch(() => { if (current) setError("Exact shared repository selection is unavailable"); });
    return () => { current = false; };
  // A refreshed installation may keep the same ID/count but have a different
  // exact repository selection. Reload it whenever the listing is refreshed.
  }, [selected]);

  async function perform(task: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await task();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Shared GitHub request failed");
    } finally {
      setBusy(false);
    }
  }

  function startSetup() {
    void perform(async () => {
      const result = await api.startSharedGithubSetup();
      setInstallUrl(verifiedInstallUrl(result.install_url));
      setMessage("Open GitHub setup, grant only required repositories and complete authorization. When Platform confirms success, refresh here and explicitly select the repositories for this Denali connection.");
    });
  }

  function useInDenali() {
    if (!selected) return;
    void perform(async () => {
      const selection = selectedGithubRepositoryIds(repositoryIds, repositories.map((repo) => repo.id));
      await api.useSharedGithubInDenali(selected.id, selection);
      await onChanged();
      setMessage("The selected repositories have their own Denali connection. Existing connections were not changed. Validate it and collect source below.");
    });
  }

  function disable() {
    if (!selected || !window.confirm("Disable this shared GitHub connection for all Transilience apps in this organization?")) return;
    void perform(async () => {
      await api.disableSharedGithub(selected.id);
      await refresh();
      setMessage("Shared GitHub disabled for this organization. Existing short-lived tokens expire separately.");
    });
  }

  if (!available) return null;
  return <section className="panel shared-aws-pilot" aria-label="Shared GitHub connection">
    <div className="shared-aws-pilot-heading">
      <div><span className="eyebrow">REUSABLE GITHUB CONNECTION</span><h3>Connect repositories once</h3><p>Platform owns this separate read-only GitHub App. Select a pinned subset for each Denali connection. Adding repositories to the installation never widens existing Denali connections. Tokens remain temporary and server-side.</p></div>
      <button type="button" onClick={() => void refresh()}>Refresh</button>
    </div>
    {canWrite && <div className="shared-aws-pilot-actions">
      <button type="button" disabled={busy} onClick={startSetup}>Connect GitHub</button>
      {installUrl && <a href={installUrl} target="_blank" rel="noopener noreferrer">Open GitHub setup ↗</a>}
    </div>}
    {items.length > 0 && <div className="shared-aws-pilot-detail">
      <label>Shared installation<select value={selected?.id ?? ""} onChange={(event) => setSelectedId(event.target.value)}>
        {items.map((item) => <option key={item.id} value={item.id}>{item.account_login} · {item.repository_count} repositories · {item.availability}</option>)}
      </select></label>
      {selected && <><p>GitHub account {selected.account_login} · installation {selected.installation_id} · {selected.repository_count} exact repositories · {selected.availability}</p>
        {repositories.length > 0 && <details open><summary>Select from {repositories.length} available repositories</summary><ul>{repositories.map((repo) => <li key={repo.id}>
          <label className="shared-github-repository-choice"><input type="checkbox" disabled={!canWrite || busy} checked={repositoryIds.includes(repo.id)} onChange={(event) => setRepositoryIds((previous) => event.target.checked ? [...previous, repo.id] : previous.filter((id) => id !== repo.id))} /> {repo.full_name} · repository ID {repo.id}{repo.archived ? " · archived" : ""}</label>
        </li>)}</ul><p>Selections reset on refresh. Each saved connection keeps its exact repository identities; a changed selection creates a separate local connection.</p></details>}
        {canWrite && <div className="shared-aws-pilot-actions">
          <button type="button" disabled={busy || selected.availability !== "ready" || repositoryIds.length === 0} onClick={useInDenali}>Use selected repositories in Denali</button>
          <button type="button" disabled={busy || selected.availability === "disabled"} onClick={disable}>Disable for organization</button>
        </div>}
      </>}
    </div>}
    {message && <p className="shared-aws-pilot-message" role="status">{message}</p>}
    {error && <p className="shared-aws-pilot-error" role="alert">{error}</p>}
  </section>;
}
