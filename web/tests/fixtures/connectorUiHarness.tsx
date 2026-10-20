/** Local visual QA only. Every API method is replaced; no real identity/provider is contacted. */
import { useState } from "react";
import { createRoot } from "react-dom/client";
import { ConnectionsPage } from "../../src/App";
import { api, type ConnectionCatalog, type SharedGoogleWorkspaceTarget } from "../../src/api";
import type { Connection } from "../../src/types";
import { applyTheme } from "../../src/theme";
import "../../src/styles.css";

if (!import.meta.env.DEV || !["localhost", "127.0.0.1", "::1"].includes(window.location.hostname)) throw new Error("This synthetic preview is local development only.");

const params = new URLSearchParams(window.location.search);
const native = params.get("source") === "native";
const empty = params.get("empty") === "1";
const readOnly = params.get("member") === "1";
const slow = params.get("slow") === "1";
const fail = params.get("error") === "1";
const providerFail = params.get("provider_error") === "1";
const collectionPreview = params.get("collection");
const providers = ["aws", "azure", "entra", "gcp", "github", "google_workspace", "azure_repos"] as const;
type Provider = typeof providers[number];
const labels: Record<Provider, string> = {aws:"Amazon Web Services", azure:"Microsoft Azure", entra:"Microsoft Entra", gcp:"Google Cloud", github:"GitHub", google_workspace:"Google Workspace", azure_repos:"Azure Repos"};
const scopes: Record<Provider, string[]> = {
  aws:["aws.bedrock_agents", "aws.agentcore", "aws.agent_runtime_activity", "aws.bedrock_activity", "aws.bedrock_logging", "aws.code_to_cloud"],
  azure:["azure.ai_services", "azure.ai_platform", "azure.ai_activity", "azure.agent_runtime_activity", "azure.code_to_cloud"],
  entra:["entra.ai_applications", "entra.permissions", "entra.sign_ins", "entra.directory_audits"],
  gcp:["gcp.vertex_ai", "gcp.agent_builder", "gcp.ai_activity", "gcp.code_to_cloud"],
  github:["github.repository_metadata", "github.repository_contents", "github.actions_workflows"],
  google_workspace:["google_workspace.gemini_activity", "google_workspace.oauth_activity"],
  azure_repos:["azure_repos.repository_metadata", "azure_repos.repository_contents"],
};
const id = (value: number) => `00000000-0000-4000-8000-${String(value).padStart(12,"0")}`;
const timestamp = new Date().toISOString();
const repositories = Array.from({length:113}, (_, index) => ({id:index + 1, node_id:`fixture-${index + 1}`, name:`service-${String(index + 1).padStart(3,"0")}`, full_name:`example/service-${String(index + 1).padStart(3,"0")}`, owner_id:1, owner_login:"example", private:true, archived:false, default_branch:"main"}));
const adoRepositories = repositories.map((repo, index) => ({...repo, id:id(1000 + index), project_id:id(2000), project_name:"Example platform", full_name:`Example platform/${repo.name}`, remote_url:null}));
const workspaceTarget: SharedGoogleWorkspaceTarget = {clerk_org_id:"org_synthetic_preview", provider:"google_workspace", target_id:id(21), customer_id:"C00FIXTURE", domain:"example.test", admin_email:"operator@example.test", service_account:"reader@example.invalid", oauth_client_id:"100000000001"};
const workspace = {...workspaceTarget, id:id(6), binding_revision:1, lifecycle_state:"active", setup_state:"ready", health_state:"healthy", declared_scopes:scopes.google_workspace, validated_scopes:scopes.google_workspace, last_validated_at:timestamp, validation_results:scopes.google_workspace.map((scope,index) => ({scope, application_name:["gemini_in_workspace_apps","token"][index], state:"passed", customer_identity_observed:true}))};
const microsoft = (provider: "azure" | "entra") => ({id:id(provider === "azure" ? 2 : 3), provider, connection_kind:`shared_${provider}`, display_name:`Example ${labels[provider]}`, tenant_id:id(31), application_client_id:id(32), subscriptions:[{id:id(33),name:"Example production"}], availability:"ready", setup_state:"ready", health_state:"healthy", validated_scopes:scopes[provider]});
const ado = {id:id(7), provider:"azure_repos", connection_kind:"shared_azure_repos", target_id:id(22), tenant_id:id(31), organization:"example", application_client_id:id(32), display_name:"Example Azure Repos", lifecycle_state:"active", setup_state:"ready", health_state:"healthy", availability:"ready", repository_count:adoRepositories.length, authority_revision:1, declared_scopes:scopes.azure_repos, validated_scopes:scopes.azure_repos, last_validated_at:timestamp};
const catalog: ConnectionCatalog = {items:providers.map((provider) => ({provider,label:labels[provider],onboarding_path:native?"native":"shared", shared_enabled:!native,native_available:true,supported_scopes:scopes[provider],supported_coverage_modes:["automatic","selected"],parity_gaps:[],reason:null,reason_code:null})),platform_only:false,platform_only_blockers:["synthetic_ui_preview"]};
function nativeCredential(provider: Provider): Connection["credential_reference"] {
  if (provider === "aws") return {type:"aws_assume_role",role_arn:"arn:aws:iam::123456789012:role/ExampleReader"};
  if (provider === "azure") return {type:"azure_multitenant_app",client_id:id(32)};
  if (provider === "entra") return {type:"entra_multitenant_app",client_id:id(32)};
  if (provider === "gcp") return {type:"gcp_service_account",principal_email:"reader@example.invalid"};
  if (provider === "github") return {type:"github_app_installation",app_id:1,installation_id:1,app_slug:"example"};
  if (provider === "azure_repos") return {type:"azure_repos_service_principal",client_id:id(32)};
  return {type:"google_workspace_domain_wide_delegation",service_account:"reader@example.invalid",oauth_client_id:"100000000001"};
}
const rows: Connection[] = providers.map((provider, index) => ({
  id:id(101+index), provider, display_name:`Example ${labels[provider]}`, lifecycle_state:provider==="github"?"disabled":"active", health_state:"healthy",
  credential_reference:native ? nativeCredential(provider) : provider==="github"?{type:"platform_shared_github",platform_connection_id:id(5),installation_id:1}:{type:`platform_shared_${provider}`,platform_connection_id:id(index+1)},
  declared_scopes:scopes[provider],coverage_plan:[],configuration:{account_id:"123456789012",partition:"aws",coverage_mode:provider==="aws"?"selected":undefined,regions:["us-east-1"],deployment_region:"us-east-1",tenant_id:id(31),subscriptions:[{id:id(33),name:"Example production"}],projects:[{id:"example-project",number:"123456789012",name:"Example project"}],domain:workspace.domain,customer_id:workspace.customer_id,admin_email:workspace.admin_email,platform_binding:{target_id:workspace.target_id,customer_id:workspace.customer_id,domain:workspace.domain,admin_email:workspace.admin_email,service_account:workspace.service_account,oauth_client_id:workspace.oauth_client_id,binding_revision:1},account_login:"example",organization:"example",repositories:provider==="azure_repos"?adoRepositories.slice(0,2):repositories.slice(0,1)},
  setup_capabilities:{cloudformation_quick_create:false,azure_cloud_shell:false,gcp_cloud_shell:false,github_app:false,azure_repos_oauth:false,entra_admin_consent:false,google_workspace_admin_authorization:false},
  last_validated_at:timestamp,last_validation:{started_at:timestamp,completed_at:timestamp,health_state:"healthy",credential_state:"passed",account_id_observed:provider==="aws"?"123456789012":id(31),summary:"Read-only access verified for the declared evidence planes. Synthetic UI fixture.",results:scopes[provider].map((scope) => ({scope,plane:scope.replace(".","_"),label:scope.split(".")[1].replaceAll("_"," "),region:"selected boundary",state:"passed",detail:"The declared read-only operation completed. Synthetic data only."}))},created_at:timestamp,updated_at:timestamp,
} as Connection));

// Collection examples remain synthetic and cannot dispatch a job or change a connection.
if (collectionPreview) {
  const github = rows.find((row) => row.provider === "github")!;
  github.lifecycle_state = params.get("disabled") === "1" ? "disabled" : "active";
  github.configuration.repositories = repositories;
  github.last_source_collection = {job_id:id(900),connection_id:github.id,state:"partial",completed_at:timestamp,repository_count:113,completed_repository_count:113,partial_count:15,failed_count:0,retained_repository_count:98,retry_repository_count:15,refreshed_repository_count:15,repositories:[]};
  github.source_collection_state = ["running","quota"].includes(collectionPreview) ? "running" : "idle";
  if (github.source_collection_state === "running") github.source_collection_progress = {job_id:id(901),state:"running",repository_count:113,completed_repository_count:102,partial_count:4,failed_count:0,retained_repository_count:98,retry_repository_count:15,refreshed_repository_count:4,resume_pending:true,retry_after_seconds:collectionPreview === "quota" ? 120 : 0,updated_at:timestamp,repositories:[]};
}

// Fail closed: even an unanticipated method cannot use the real API transport.
for (const method of Object.keys(api)) (api as unknown as Record<string,unknown>)[method] = async () => {throw new Error("This is a read-only synthetic UI preview. No API or provider action was performed.");};
const respond = <T,>(value: T, isCatalog = false) => async () => {
  await new Promise<void>((resolve) => window.setTimeout(resolve, slow ? 7000 : 180));
  if (fail || (providerFail && !isCatalog)) throw new Error("The access service is temporarily unavailable. Synthetic failure for UI testing.");
  return value;
};
Object.assign(api, {
  connectionCatalog:respond(catalog,true), sharedAwsConnections:respond({items:empty?[]:[{id:id(1),provider:"aws",connection_kind:"shared_aws",partition:"aws",deployment_region:"us-east-1",coverage_mode:"selected",regions:["us-east-1"],external_account_id:"123456789012",availability:"ready",validated_scopes:scopes.aws,last_validated_at:timestamp}]}),
  sharedAwsValidation:respond({job_state:null,health_state:"healthy",credential_state:"passed",job_error_code:null,validation_summary:"Read-only AWS access verified."}),
  sharedMicrosoftConnections:async (provider:"azure"|"entra") => respond({items:empty?[]:[microsoft(provider)]})(), sharedMicrosoftStatus:respond({job_state:null,setup_state:"ready",health_state:"healthy"}),
  sharedGcpConnections:respond({items:empty?[]:[{id:id(4),provider:"gcp",connection_kind:"shared_gcp",display_name:"Example Google Cloud",projects:[{id:"example-project",number:"123456789012"}],availability:"ready",validated_scopes:scopes.gcp}]}), sharedGcpStatus:respond({job_state:null,setup_state:"ready",health_state:"healthy",error_code:null,retry_available:true}),
  sharedGithubConnections:respond({items:empty?[]:[{id:id(5),provider:"github",connection_kind:"shared_github",account_id:1,account_login:"example",installation_id:1,repository_selection:"all",repository_count:repositories.length,availability:"ready",validated_scopes:scopes.github,last_validated_at:timestamp}]}), sharedGithubRepositories:respond({items:repositories}),
  sharedGoogleWorkspaceConfig:respond({enabled:true,items:[workspaceTarget],declared_scopes:scopes.google_workspace,authorization_scope:"https://www.googleapis.com/auth/admin.reports.audit.readonly",setup_method:"domain_wide_delegation"}), sharedGoogleWorkspaceInventory:respond({items:empty?[]:[workspace]}), sharedGoogleWorkspaceStatus:respond(workspace),
  sharedAzureReposConfig:respond({items:[ado]}), sharedAzureReposConnections:respond({items:empty?[]:[ado]}), sharedAzureReposStatus:respond(ado),sharedAzureReposRepositories:respond({items:adoRepositories}),
});

applyTheme(params.get("theme")==="light"?"light":"dark",{persist:false});
function Harness() {
  const requested = params.get("provider") as Provider;
  const [query,setQuery] = useState<Record<string,string>>(collectionPreview ? {connection:rows.find((row) => row.provider === "github")!.id} : {new:"1",provider:providers.includes(requested)?requested:"azure"});
  const [theme,setTheme] = useState(params.get("theme")==="light"?"light":"dark");
  const update = (values:Record<string,string|null|undefined>) => setQuery((previous) => {
    const next = {...previous}; for(const [key,value] of Object.entries(values)) {if(value) next[key]=value; else delete next[key];} return next;
  });
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><strong>Denali</strong><span>Connector UI preview</span></div><nav aria-label="Preview navigation"><button className="active">Connections</button></nav><p>Synthetic data only.<br/>All API actions are blocked.</p></aside><main className="main-shell"><header className="topbar"><div><span className="eyebrow">LOCAL UI QA</span><h1>Connections</h1></div><div className="topbar-actions"><span>Example workspace · no provider calls</span><button type="button" className="secondary-action" onClick={() => {const next=theme==="dark"?"light":"dark";setTheme(next);applyTheme(next,{persist:false});}}>Switch to {theme==="dark"?"light":"dark"} theme</button></div></header><div className="workspace"><ConnectionsPage connections={empty?[]:rows} selectedId={query.connection} showCreate={query.new==="1"} navigation={{values:query,set:(key,value,defaultValue="")=>update({[key]:value===defaultValue?null:value}),clear:(keys)=>update(Object.fromEntries(keys.map((key)=>[key,null]))),update}} onSelect={(connection) => setQuery(connection?{connection}:{})} onShowCreate={(visible)=>update({new:visible?"1":null,manage:null,onboarding:null})} onChanged={async()=>{}} onOperationAccepted={()=>{}} entraSetupReturn={null} githubSetupReturn={null} azureReposSetupReturn={null} canWrite={!readOnly}/></div></main></div>;
}
createRoot(document.getElementById("root")!).render(<Harness/>);
