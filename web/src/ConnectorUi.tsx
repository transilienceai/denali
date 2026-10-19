import { CircleAlert, CloudCog, RefreshCw } from "lucide-react";
import { useId, type ReactNode } from "react";

/** A visible, announced placeholder; loading is never presented as an empty catalog. */
export function ConnectorLoadingState({ label, detail, compact = false }: { label: string; detail?: string; compact?: boolean }) {
  return <div className={`connector-loading${compact ? " compact" : ""}`} aria-busy="true">
    <div className="connector-loading-heading" role="status" aria-live="polite"><RefreshCw className="spin" aria-hidden="true" /><div><strong>{label}</strong>{detail && <p>{detail}</p>}</div></div>
    <div className="connector-skeleton" aria-hidden="true"><span /><span />{!compact && <div><span /><span /></div>}</div>
  </div>;
}

export function ConnectorErrorState({ message, onRetry, retrying = false }: { message: string; onRetry?: () => void; retrying?: boolean }) {
  return <div className="connector-panel-state connector-panel-error" role="alert"><CircleAlert aria-hidden="true" /><div><strong>Unable to load this connection setup</strong><p>{message}</p></div>{onRetry && <button type="button" className="secondary-action" disabled={retrying} onClick={onRetry}>{retrying ? "Retrying…" : "Try again"}</button>}</div>;
}

export function ConnectorEmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="connector-panel-state"><CloudCog aria-hidden="true" /><div><strong>{title}</strong>{children && <div className="connector-field-hint">{children}</div>}</div></div>;
}

type ScopeOption = { id: string; label: string; detail?: string };
const SCOPE_COPY: Record<string, Omit<ScopeOption, "id">> = {
  "aws.bedrock_agents": { label: "Bedrock agents & guardrails", detail: "Agent and guardrail inventory." },
  "aws.agentcore": { label: "AgentCore inventory", detail: "Runtime, gateway, identity and memory metadata." },
  "aws.agent_runtime_activity": { label: "AgentCore runtime activity", detail: "Metadata-only sessions, model calls and tool invocations." },
  "aws.bedrock_activity": { label: "Bedrock management activity", detail: "Bounded CloudTrail event history." },
  "aws.bedrock_logging": { label: "Invocation logging configuration", detail: "Configuration only, never prompts or responses." },
  "aws.code_to_cloud": { label: "Code-to-cloud deployments", detail: "Deployment identities and runtime roles." },
  "azure.ai_services": { label: "AI services", detail: "AI service accounts and Azure AI Search." },
  "azure.ai_platform": { label: "AI platform", detail: "Machine Learning workspaces and Bot Service." },
  "azure.ai_activity": { label: "AI management activity", detail: "Subscription Activity Log metadata." },
  "azure.agent_runtime_activity": { label: "Foundry runtime activity", detail: "Metadata-only Application Insights sessions and tool calls." },
  "azure.code_to_cloud": { label: "Code-to-cloud deployments", detail: "Container Apps, Function Apps and AKS identities." },
  "entra.ai_applications": { label: "AI applications", detail: "Catalog-matched enterprise applications." },
  "entra.permissions": { label: "OAuth permissions", detail: "Delegated grants and application permissions." },
  "entra.sign_ins": { label: "Application sign-ins", detail: "Bounded sign-in metadata; no tokens retained." },
  "entra.directory_audits": { label: "Directory changes", detail: "Application-management audit metadata." },
  "gcp.vertex_ai": { label: "Vertex AI", detail: "Model, dataset, pipeline and notebook inventory." },
  "gcp.agent_builder": { label: "Agent Builder & Dialogflow", detail: "Search and conversational agent inventory." },
  "gcp.ai_activity": { label: "AI management activity", detail: "Cloud Audit Log metadata." },
  "gcp.code_to_cloud": { label: "Code-to-cloud deployments", detail: "Cloud Run, functions and GKE identities." },
  "github.repository_metadata": { label: "Repository metadata", detail: "Exact repository identity and basic metadata." },
  "github.repository_contents": { label: "Repository source analysis", detail: "Read the default revision; no source writes." },
  "github.actions_workflows": { label: "GitHub Actions metadata", detail: "Workflow inventory; no secrets or writes." },
  "azure_repos.repository_metadata": { label: "Repository metadata", detail: "Exact repository and project identity." },
  "azure_repos.repository_contents": { label: "Repository source analysis", detail: "Read the default revision; no source writes." },
  "google_workspace.gemini_activity": { label: "Gemini activity", detail: "Bounded feature-use metadata; no prompts or responses." },
  "google_workspace.oauth_activity": { label: "AI OAuth activity", detail: "Catalog-matched application authorization events." },
};

/** Presentation only. Selections/defaults and provider authority remain with the caller. */
export function EvidenceScopePicker({ label = "Read-only evidence", ariaLabel, scopes, selected, onChange, disabled = false, requiredScopes = [], help, options }: {
  label?: string;
  ariaLabel?: string;
  scopes: readonly string[];
  selected: readonly string[];
  onChange: (scopes: string[]) => void;
  disabled?: boolean;
  requiredScopes?: readonly string[];
  help?: ReactNode;
  options?: readonly ScopeOption[];
}) {
  const helpId = useId();
  return <fieldset className="connector-evidence-picker" aria-label={ariaLabel} disabled={disabled} aria-describedby={help ? helpId : undefined}>
    <legend>{label}</legend>
    {help && <p className="connector-field-hint" id={helpId}>{help}</p>}
    <div className="connector-choice-grid">{scopes.map((scope) => {
      const option = options?.find((candidate) => candidate.id === scope) ?? SCOPE_COPY[scope];
      const required = requiredScopes.includes(scope);
      return <label className="connector-choice" key={scope} data-selected={selected.includes(scope)}>
        <input type="checkbox" checked={selected.includes(scope)} disabled={disabled || required} onChange={(event) => onChange(event.target.checked ? [...selected, scope] : selected.filter((item) => item !== scope))} />
        <span className="connector-choice-copy"><strong>{option?.label ?? scope.split(".").pop()?.replaceAll("_", " ")}{required && <span className="connector-required">Required</span>}</strong>{option?.detail && <small>{option.detail}</small>}</span>
      </label>;
    })}</div>
  </fieldset>;
}
