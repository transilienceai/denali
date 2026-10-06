import { Check, ExternalLink, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import { githubConnectionPresentation } from "./githubConnectionPresentation";

export function GitHubSetupStep({ credentialType, setupComplete, preparing, canLaunch, onPrepare, children }: {
  credentialType: string;
  setupComplete: boolean;
  preparing: boolean;
  canLaunch: boolean;
  onPrepare: () => void;
  children?: ReactNode;
}) {
  const presentation = githubConnectionPresentation(credentialType);
  return <div className={setupComplete ? "complete" : "current"}>
    <span>{setupComplete ? <Check /> : "2"}</span>
    <div>
      <strong>{presentation.setupTitle}</strong>
      <small>{presentation.setupDetail}</small>
      {presentation.shared ? <small>{presentation.setupHint}</small> : <>
        <button className="primary-action" aria-busy={preparing} disabled={preparing || !canLaunch} onClick={onPrepare}>
          {preparing ? <RefreshCw className="spin" /> : <ExternalLink />}
          {preparing ? "Opening GitHub…" : setupComplete ? "Reconfigure GitHub App" : "Install / configure GitHub App"}
        </button>
        {!canLaunch && <small className="launch-unavailable">{presentation.setupHint}</small>}
      </>}
      {children}
    </div>
  </div>;
}
