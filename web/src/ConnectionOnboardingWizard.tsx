import { Check, RefreshCw, ShieldCheck, X } from "lucide-react";
import type { ReactNode } from "react";
import type { ConnectionCatalogItem } from "./api";
import type { Connection } from "./types";
import { connectionCoverageNotes, connectionJourney, type ConnectionJourneyPhase } from "./connectionOnboarding";

export function ConnectionJourney({ connection, phase }: { connection?: Connection; phase?: ConnectionJourneyPhase }) {
  return <ol className="connection-journey" aria-label="Connection progress">
    {connectionJourney(connection, phase).map((step, index) => <li key={step.label} className={step.state} aria-current={step.state === "current" ? "step" : undefined}>
      <span>{step.state === "complete" ? <Check aria-hidden="true" /> : index + 1}</span><strong>{step.label}</strong>
    </li>)}
  </ol>;
}

export function ConnectionOnboardingWizard({
  items, provider, loading, error, nativeRequested, phase, managing, onProvider, onNative, onRetry, onClose, children,
}: {
  items: ConnectionCatalogItem[];
  provider: Connection["provider"];
  loading: boolean;
  error: string | null;
  nativeRequested: boolean;
  phase: ConnectionJourneyPhase;
  managing: boolean;
  onProvider: (provider: Connection["provider"]) => void;
  onNative: (native: boolean) => void;
  onRetry: () => void;
  onClose: () => void;
  children: ReactNode;
}) {
  const selected = items.find((item) => item.provider === provider);
  const coverageNotes = selected ? connectionCoverageNotes(selected) : [];
  return <section className="panel connection-onboarding-wizard" aria-label="Connect an evidence source">
    <div className="connection-wizard-heading"><div><span className="eyebrow">{managing ? "MANAGE SOURCE ACCESS" : "ADD AN EVIDENCE SOURCE"}</span><h3>{managing ? "Review access and selected resources" : "Choose the source to connect"}</h3><p>Grant read access, verify the selected resources, then collect evidence.</p></div><button type="button" className="drawer-close" onClick={onClose} aria-label="Close connection setup"><X /></button></div>
    {loading ? <p role="status"><RefreshCw className="spin" /> Checking available connection methods…</p> : error ? <div className="connection-error" role="alert"><span>{error}</span><button type="button" onClick={onRetry}>Try again</button></div> : <>
      <div className="connection-provider-picker" role="group" aria-label="Evidence source">{items.map((item) => <button key={item.provider} type="button" aria-pressed={provider === item.provider} className={provider === item.provider ? "active" : ""} onClick={() => onProvider(item.provider)}>{item.label}</button>)}</div>
      <ConnectionJourney phase={phase} />
      {selected?.onboarding_path === "shared" && <div className="connection-method-note"><ShieldCheck /><div><strong>{nativeRequested ? "Denali connection" : "Reusable organization connection"}</strong><p>{nativeRequested ? "This setup remains dedicated to Denali." : "Use your organization’s verified access across authorized Transilience applications."}</p>{coverageNotes.length > 0 && <p>{coverageNotes.join(" ")}</p>}{selected.native_available && !managing && <button type="button" onClick={() => onNative(!nativeRequested)}>{nativeRequested ? "Use reusable connection setup" : "Need other collection coverage? Use Denali setup"}</button>}</div></div>}
      {selected?.onboarding_path === "unavailable" ? <p role="status">{selected.reason ?? "This connection method is not available for this organization."}</p> : children}
    </>}
  </section>;
}
