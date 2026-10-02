import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type SharedAwsConnection, type SharedAwsValidation } from "./api";

export function SharedAwsPilot({ canWrite, onChanged }: { canWrite: boolean; onChanged: () => Promise<void> }) {
  const [available, setAvailable] = useState(false);
  const [items, setItems] = useState<SharedAwsConnection[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [accountId, setAccountId] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [validation, setValidation] = useState<SharedAwsValidation | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const selected = items.find((item) => item.id === selectedId) ?? items[0];

  const refresh = useCallback(async () => {
    try {
      const result = await api.sharedAwsConnections();
      setItems(result.items.filter((item) => item.connection_kind === "shared_aws"));
      setAvailable(true);
    } catch {
      setAvailable(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const refreshValidation = useCallback(async (id: string) => {
    try {
      const result = await api.sharedAwsValidation(id);
      setValidation(result);
      if (result.job_state === "succeeded" || result.job_state === "failed") void refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Validation status is unavailable");
    }
  }, [refresh]);

  useEffect(() => {
    if (!selected || !["queued", "running"].includes(validation?.job_state ?? "")) return;
    const timer = window.setInterval(() => void refreshValidation(selected.id), 3000);
    return () => window.clearInterval(timer);
  }, [selected, validation?.job_state, refreshValidation]);

  async function perform(action: string, task: () => Promise<void>) {
    if (busy) return;
    setBusy(action);
    setMessage("");
    setError("");
    try {
      await task();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Shared AWS request failed");
    } finally {
      setBusy(null);
    }
  }

  function create(event: FormEvent) {
    event.preventDefault();
    void perform("create", async () => {
      const created = await api.createSharedAwsConnection(accountId.trim(), region.trim());
      await refresh();
      setSelectedId(created.id);
      setMessage("Shared connection registered. Deploy its read-only role, then validate.");
    });
  }

  function download() {
    if (!selected) return;
    void perform("download", async () => {
      const blob = await api.sharedAwsTemplate(selected.id);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `transilience-shared-aws-${selected.external_account_id}.yaml`;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }

  function validate() {
    if (!selected) return;
    void perform("validate", async () => {
      await api.validateSharedAws(selected.id);
      setValidation({
        job_state: "queued", health_state: "unknown", credential_state: "unknown",
        job_error_code: null, validation_summary: null,
      });
      setMessage("Validation started. Status will update here.");
    });
  }

  function probe() {
    if (!selected) return;
    void perform("probe", async () => {
      const result = await api.probeSharedAws(selected.id, region.trim());
      setMessage(`Scoped ${result.scope} read passed in ${result.region}; sampled ${result.sample_count} agent record(s).`);
    });
  }

  function useInDenali() {
    if (!selected) return;
    void perform("use", async () => {
      await api.useSharedAwsInDenali(selected.id, region.trim());
      await onChanged();
      setMessage("Shared AWS is available in Denali connections. Validate it there, then collect the selected Region and scope.");
    });
  }

  function disable() {
    if (!selected || !window.confirm("Disable this shared AWS connection for this organization?")) return;
    void perform("disable", async () => {
      await api.disableSharedAws(selected.id);
      await refresh();
      setMessage("Shared connection disabled. Previously issued sessions expire within 15 minutes.");
    });
  }

  if (!available) return null;
  return <section className="panel shared-aws-pilot" aria-label="Shared AWS pilot">
    <div className="shared-aws-pilot-heading">
      <div><span className="eyebrow">SHARED CONNECTION PILOT</span><h3>Shared AWS connection</h3><p>This opt-in path creates a reusable read-only platform role. Add a ready connection to Denali to validate and collect with scoped temporary access; existing Denali roles remain unchanged.</p></div>
      <button type="button" onClick={() => void refresh()}>Refresh</button>
    </div>
    {canWrite && <form className="shared-aws-pilot-form" onSubmit={create}>
      <label>AWS account ID<input required inputMode="numeric" pattern="[0-9]{12}" maxLength={12} value={accountId} onChange={(event) => setAccountId(event.target.value)} placeholder="123456789012" /></label>
      <label>Selected Region<input required value={region} onChange={(event) => setRegion(event.target.value)} placeholder="us-east-1" /></label>
      <button className="primary-action" disabled={busy !== null}>Register shared AWS</button>
    </form>}
    {items.length > 0 && <div className="shared-aws-pilot-detail">
      <label>Shared connection<select value={selected?.id ?? ""} onChange={(event) => { setSelectedId(event.target.value); setValidation(null); }}>
        {items.map((item) => <option key={item.id} value={item.id}>{item.external_account_id} · {item.availability}</option>)}
      </select></label>
      {selected && <><p>Account {selected.external_account_id} · {selected.partition} · {selected.availability}</p>
        {canWrite && <div className="shared-aws-pilot-actions">
          <button type="button" disabled={busy !== null} onClick={download}>Download role template</button>
          <button type="button" disabled={busy !== null || selected.availability === "disabled"} onClick={validate}>Validate</button>
          <button type="button" disabled={busy !== null || selected.availability !== "ready"} onClick={probe}>Test scoped AWS read</button>
          <button type="button" disabled={busy !== null || selected.availability !== "ready"} onClick={useInDenali}>Use in Denali</button>
          <button type="button" disabled={busy !== null || selected.availability === "disabled"} onClick={disable}>Disable</button>
        </div>}
        {validation && <p role="status">Validation: {validation.job_state ?? "not started"} · {validation.health_state}{validation.validation_summary ? ` · ${validation.validation_summary}` : ""}</p>}
      </>}
    </div>}
    {message && <p className="shared-aws-pilot-message" role="status">{message}</p>}
    {error && <p className="shared-aws-pilot-error" role="alert">{error}</p>}
  </section>;
}
