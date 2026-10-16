import { Check, ShieldCheck, X } from "lucide-react";
import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import type { ConnectionCatalogItem } from "./api";
import type { Connection } from "./types";
import { connectionCoverageNotes, connectionJourney, type ConnectionJourneyPhase } from "./connectionOnboarding";
import { ConnectorEmptyState, ConnectorErrorState, ConnectorLoadingState } from "./ConnectorUi";

const PROVIDER_ICONS: Record<Connection["provider"], string> = {
  aws: "aws", azure: "azure", entra: "entra", gcp: "gcp", github: "github", google_workspace: "google-workspace", azure_repos: "azure-repos",
};

export function ConnectionJourney({ connection, phase }: { connection?: Connection; phase?: ConnectionJourneyPhase }) {
  return <ol className="connection-journey" aria-label="Connection progress">
    {connectionJourney(connection, phase).map((step, index) => <li key={step.label} className={step.state} aria-current={step.state === "current" ? "step" : undefined}>
      <span>{step.state === "complete" ? <Check aria-hidden="true" /> : index + 1}</span><strong>{step.label}</strong>
    </li>)}
  </ol>;
}

export function ConnectionOnboardingWizard({
  items, provider, loading, loadingLabel, error, nativeRequested, phase, managing, onProvider, onNative, onRetry, onClose, children,
}: {
  items: ConnectionCatalogItem[];
  provider: Connection["provider"];
  loading: boolean;
  loadingLabel?: string;
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
  const id = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  const selected = items.find((item) => item.provider === provider);
  const coverageNotes = selected ? connectionCoverageNotes(selected) : [];
  function moveProvider(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const next = event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : event.key === "ArrowRight" ? (index + 1) % items.length : event.key === "ArrowLeft" ? (index - 1 + items.length) % items.length : null;
    if (next === null) return;
    event.preventDefault();
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
    if (items[next].provider !== provider) onProvider(items[next].provider);
  }
  return <section className="panel connection-onboarding-wizard" aria-label="Connect an evidence source">
    <div className="connection-wizard-heading"><div><span className="eyebrow">{managing ? "MANAGE SOURCE ACCESS" : "ADD AN EVIDENCE SOURCE"}</span><h3 ref={heading} tabIndex={-1}>{managing ? "Review access and selected resources" : "Choose the source to connect"}</h3><p>Grant read access, verify the selected resources, then collect evidence.</p></div><button type="button" className="drawer-close" onClick={onClose} aria-label="Close connection setup"><X /></button></div>
    {loading ? <ConnectorLoadingState label={loadingLabel ?? "Checking available connection methods…"} detail="Your setup will appear here when its access information is ready." /> : error ? <ConnectorErrorState message={error} onRetry={onRetry} /> : <>
      <div className="connection-provider-picker" role="tablist" aria-label="Evidence source">{items.map((item, index) => <button key={item.provider} id={`${id}-${item.provider}`} role="tab" type="button" aria-selected={provider === item.provider} aria-controls={`${id}-panel`} tabIndex={provider === item.provider || (!selected && index === 0) ? 0 : -1} className={`connection-provider-tab${provider === item.provider ? " active" : ""}`} onClick={() => { if (provider !== item.provider) onProvider(item.provider); }} onKeyDown={(event) => moveProvider(event, index)}>{item.label}<img className="connection-provider-tab-icon" src={`/provider-icons/${PROVIDER_ICONS[item.provider]}.svg`} alt="" aria-hidden="true" /></button>)}</div>
      <ConnectionJourney phase={phase} />
      {selected?.onboarding_path === "shared" && <div className="connection-method-note"><ShieldCheck aria-hidden="true" /><div><strong>{nativeRequested ? "Denali connection" : "Reusable organization connection"}</strong><p>{nativeRequested ? "Dedicated to Denali. Existing connections are not migrated." : "Use verified access across your authorized applications."}</p>{coverageNotes.length > 0 && <p>{coverageNotes.join(" ")}</p>}</div>{selected.native_available && !managing && <button type="button" onClick={() => onNative(!nativeRequested)}>{nativeRequested ? "Use reusable connection setup" : "Use Denali setup instead"}</button>}</div>}
      <p className="connector-security-note"><ShieldCheck aria-hidden="true" />Access verification and evidence collection are separate. Neither is a security verdict.</p>
      <div className="connection-provider-panel" id={`${id}-panel`} role="tabpanel" aria-labelledby={selected ? `${id}-${selected.provider}` : undefined} tabIndex={0}>
        {!selected || selected.onboarding_path === "unavailable" ? <ConnectorEmptyState title="Connection setup unavailable">{selected?.reason ?? "This connection method is not available for this organization."}</ConnectorEmptyState> : children}
      </div>
    </>}
  </section>;
}
