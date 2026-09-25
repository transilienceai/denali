import { useCallback, useEffect, useState } from "react";
import { api, type SharedGitHubConnection } from "./api";

export function SharedGitHubPilot({ canWrite, onChanged }: { canWrite: boolean; onChanged: () => Promise<void> }) {
  const [available, setAvailable] = useState(false);
  const [items, setItems] = useState<SharedGitHubConnection[]>([]);
  const [selectedId, setSelectedId] = useState("");
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
    } catch {
      setAvailable(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

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
      if (!result.install_url.startsWith("https://github.com/apps/")) {
        throw new Error("GitHub setup link is invalid");
      }
      setInstallUrl(result.install_url);
      setMessage("Open GitHub setup, choose the repositories, then return here and refresh.");
    });
  }

  function useInDenali() {
    if (!selected) return;
    void perform(async () => {
      await api.useSharedGithubInDenali(selected.id);
      await onChanged();
      setMessage("Shared GitHub is now in Denali. Validate it and collect source below.");
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
  return <section className="panel shared-aws-pilot" aria-label="Shared GitHub pilot">
    <div className="shared-aws-pilot-heading">
      <div><span className="eyebrow">SHARED CONNECTION PILOT</span><h3>Shared GitHub connection</h3><p>Connect once through the Platform GitHub App, then reuse the same selected repositories in Denali and other Transilience apps. Denali keeps no App private key or installation token for this connection.</p></div>
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
        {canWrite && <div className="shared-aws-pilot-actions">
          <button type="button" disabled={busy || selected.availability !== "ready"} onClick={useInDenali}>Use in Denali</button>
          <button type="button" disabled={busy || selected.availability === "disabled"} onClick={disable}>Disable for organization</button>
        </div>}
      </>}
    </div>}
    {message && <p className="shared-aws-pilot-message" role="status">{message}</p>}
    {error && <p className="shared-aws-pilot-error" role="alert">{error}</p>}
  </section>;
}
