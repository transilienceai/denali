import {
  Activity,
  AppWindow,
  Bot,
  Boxes,
  BrainCircuit,
  Bug,
  Check,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  CircleHelp,
  Clock3,
  CloudCog,
  Code2,
  Database,
  Download,
  ExternalLink,
  FileCode2,
  Filter,
  Fingerprint,
  Gauge,
  GitBranch,
  LayoutDashboard,
  Link2,
  ListFilter,
  Menu,
  MessageSquareText,
  Mountain,
  Network,
  PanelLeftClose,
  Package,
  PackageCheck,
  Plus,
  Power,
  RefreshCw,
  Search,
  ServerCog,
  ShieldCheck,
  Sparkles,
  Trash2,
  UserRound,
  Waypoints,
  X,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "./api";
import {
  AI_APPLICATION_DISCOVERY_LABEL,
  closeDrawerTransition,
  drawerTabTransition,
  inventoryQuery,
  navigationFromUrl,
  navigationUrl,
  openDrawerTransition,
  queryWith,
  withoutDrawer,
  type DrawerKind,
  type NavigationLocation,
  type Page,
} from "./navigation";
import { applicableDetectionEvaluations } from "./presentation";
import type {
  Asset,
  AssetDetail,
  AwsConnectionCreate,
  AzureConnectionCreate,
  AzureSetupLaunch,
  GcpConnectionCreate,
  GcpSetupLaunch,
  GitHubConnectionCreate,
  CodeToCloudDeployment,
  CodeToCloudObservation,
  Connection,
  ConnectionValidationResult,
  Coverage,
  Finding,
  FindingDetail,
  FindingSeverity,
  FindingSummary,
  Issue,
  IssueDetail,
  IssueEvaluation,
  IssueSummary,
  Relationship,
  RuntimeActivity,
  RuntimeActivityDetail,
  RuntimeActivitySummary,
  RuntimeDetection,
  RuntimeDetectionDetail,
  RuntimeDetectionEvaluation,
  RuntimeDetectionSummary,
  Summary,
  Vulnerability,
  VulnerabilityDetail,
  VulnerabilitySummary,
} from "./types";

type DetailTab = "overview" | "relationships" | "evidence";
type FindingDetailTab = "overview" | "evidence" | "history";
type IssueDetailTab = "overview" | "path" | "evidence";
type VulnerabilityDetailTab = "overview" | "evidence" | "sources";
type DetectionDetailTab = "overview" | "evidence";
type FilterNavigation = {
  values: Readonly<Record<string, string>>;
  set: (
    key: string,
    value: string,
    defaultValue?: string,
    mode?: "push" | "replace",
  ) => void;
  clear: (keys: string[]) => void;
};

const KIND_META: Record<string, { label: string; plural: string; icon: LucideIcon; color: string }> = {
  ai_agent: { label: "AI agent", plural: "AI agents", icon: Bot, color: "coral" },
  ai_application: { label: "AI application", plural: "AI applications", icon: AppWindow, color: "blue" },
  ai_model: { label: "AI model", plural: "AI models", icon: BrainCircuit, color: "violet" },
  mcp_server: { label: "MCP server", plural: "MCP servers", icon: ServerCog, color: "teal" },
  ai_tool: { label: "AI tool", plural: "AI tools", icon: Zap, color: "amber" },
  ai_guardrail: { label: "Guardrail", plural: "Guardrails", icon: ShieldCheck, color: "green" },
  ai_framework: { label: "AI framework", plural: "AI frameworks", icon: Boxes, color: "blue" },
  ai_pipeline: { label: "AI pipeline", plural: "AI pipelines", icon: GitBranch, color: "blue" },
  ai_datastore: { label: "AI datastore", plural: "AI datastores", icon: Database, color: "green" },
  ai_workload: { label: "AI workload", plural: "AI workloads", icon: Activity, color: "coral" },
  code_repository: { label: "Code repository", plural: "Code repositories", icon: Code2, color: "slate" },
  identity: { label: "Identity", plural: "Identities", icon: Fingerprint, color: "violet" },
  software_component: { label: "Software component", plural: "Software components", icon: Package, color: "amber" },
};

const FALLBACK_META = { label: "Resource", plural: "Resources", icon: Boxes, color: "slate" };

function meta(kind: string) {
  return KIND_META[kind] ?? {
    ...FALLBACK_META,
    label: titleCase(kind),
    plural: titleCase(kind),
  };
}

function titleCase(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function shortKey(value: string) {
  const pieces = value.split(":");
  return pieces.at(-1)?.replaceAll("-", " ") ?? value;
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

type AzureConsentReturn = {
  connectionId: string;
  state: "succeeded" | "failed";
  tenantId?: string;
  detail?: string;
};

type GitHubSetupReturn = {
  connectionId: string;
  state: "succeeded" | "failed";
  detail?: string;
};

function readAzureConsentReturn(): AzureConsentReturn | null {
  const query = new URLSearchParams(window.location.search);
  const connectionId = query.get("state") ?? "";
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(connectionId)) return null;
  if (query.get("admin_consent")?.toLowerCase() === "true") {
    return {
      connectionId,
      state: "succeeded",
      tenantId: query.get("tenant") ?? undefined,
    };
  }
  const error = query.get("error");
  if (!error) return null;
  const description = query.get("error_description")?.trim();
  return {
    connectionId,
    state: "failed",
    detail: `${error}${description ? `: ${description.slice(0, 500)}` : ""}`,
  };
}

function readGitHubSetupReturn(): GitHubSetupReturn | null {
  const query = new URLSearchParams(window.location.search);
  const connectionId = query.get("connection_id") ?? "";
  const state = query.get("github_setup");
  if (state !== "succeeded" && state !== "failed") return null;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(connectionId)) return null;
  return { connectionId, state, detail: query.get("detail")?.slice(0, 500) || undefined };
}

function App({ canWrite = true, accountControls, profilePage }: { canWrite?: boolean; accountControls?: ReactNode; profilePage?: ReactNode }) {
  const [azureConsentReturn] = useState(readAzureConsentReturn);
  const [githubSetupReturn] = useState(readGitHubSetupReturn);
  const [navigation, setNavigation] = useState<NavigationLocation>(() =>
    navigationFromUrl(window.location.href),
  );
  const page = navigation.page;
  const [summary, setSummary] = useState<Summary | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [coverage, setCoverage] = useState<Coverage[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [findingSummary, setFindingSummary] = useState<FindingSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [vulnerabilitySummary, setVulnerabilitySummary] = useState<VulnerabilitySummary | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [issueSummary, setIssueSummary] = useState<IssueSummary | null>(null);
  const [issues, setIssues] = useState<Issue[]>([]);
  const [issueEvaluations, setIssueEvaluations] = useState<IssueEvaluation[]>([]);
  const [deployments, setDeployments] = useState<CodeToCloudDeployment[]>([]);
  const [codeToCloudObservations, setCodeToCloudObservations] = useState<CodeToCloudObservation[]>([]);
  const [activitySummary, setActivitySummary] = useState<RuntimeActivitySummary | null>(null);
  const [activities, setActivities] = useState<RuntimeActivity[]>([]);
  const [detectionSummary, setDetectionSummary] = useState<RuntimeDetectionSummary | null>(null);
  const [detections, setDetections] = useState<RuntimeDetection[]>([]);
  const [detectionEvaluations, setDetectionEvaluations] = useState<RuntimeDetectionEvaluation[]>([]);
  const [includeActivityFixtures, setIncludeActivityFixtures] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    const initial = navigationFromUrl(window.location.href);
    const canonical = navigationUrl(initial.page, initial.query);
    const overlayParent = initial.drawer
      ? navigationUrl(initial.page, withoutDrawer(initial.query))
      : undefined;
    window.history.replaceState(
      {
        ...window.history.state,
        denali: true,
        page: initial.page,
        overlayDepth: Number(window.history.state?.overlayDepth) || 0,
        overlayParent,
      },
      "",
      canonical,
    );
    setNavigation(initial);

    const handlePopState = () => {
      setNavigation(navigationFromUrl(window.location.href));
      setSidebarOpen(false);
    };

    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const loadAll = useCallback(async () => {
    setError(null);
    try {
      const [
        summaryResult,
        connectionsResult,
        assetsResult,
        coverageResult,
        findingSummaryResult,
        findingsResult,
        vulnerabilitySummaryResult,
        vulnerabilitiesResult,
        issueSummaryResult,
        issuesResult,
        issueEvaluationsResult,
        deploymentsResult,
        codeToCloudObservationsResult,
        activitySummaryResult,
        activityResult,
        detectionSummaryResult,
        detectionsResult,
        detectionEvaluationsResult,
      ] = await Promise.all([
        api.summary(),
        api.connections(),
        api.assets(),
        api.coverage(),
        api.findingSummary(),
        api.findings(),
        api.vulnerabilitySummary(),
        api.vulnerabilities(),
        api.issueSummary(),
        api.issues(),
        api.issueEvaluations(),
        api.codeToCloudDeployments(),
        api.codeToCloudObservations(),
        api.activitySummary(),
        api.activity(),
        api.detectionSummary(),
        api.detections(),
        api.detectionEvaluations(),
      ]);
      setSummary(summaryResult);
      setConnections(connectionsResult.items);
      setAssets(assetsResult.items);
      setCoverage(coverageResult.items);
      setFindingSummary(findingSummaryResult);
      setFindings(findingsResult.items);
      setVulnerabilitySummary(vulnerabilitySummaryResult);
      setVulnerabilities(vulnerabilitiesResult.items);
      setIssueSummary(issueSummaryResult);
      setIssues(issuesResult.items);
      setIssueEvaluations(issueEvaluationsResult.items);
      setDeployments(deploymentsResult.items);
      setCodeToCloudObservations(codeToCloudObservationsResult.items);
      setActivitySummary(activitySummaryResult);
      setActivities(activityResult.items);
      setDetectionSummary(detectionSummaryResult);
      setDetections(detectionsResult.items);
      setDetectionEvaluations(detectionEvaluationsResult.items);
      setIncludeActivityFixtures(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to reach the Denali API");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const hasRunningConnection = connections.some(
    (connection) => connection.validation_state === "running",
  );

  useEffect(() => {
    if (!hasRunningConnection) return;
    let cancelled = false;
    let requestInFlight = false;

    const refreshConnections = async () => {
      if (requestInFlight) return;
      requestInFlight = true;
      try {
        const result = await api.connections();
        if (!cancelled) setConnections(result.items);
      } catch (cause) {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : "Unable to refresh connection validation");
        }
      } finally {
        requestInFlight = false;
      }
    };

    void refreshConnections();
    const timer = window.setInterval(() => void refreshConnections(), 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [hasRunningConnection]);

  useEffect(() => {
    if (!azureConsentReturn && !githubSetupReturn) return;
    commitNavigation(
      "connections",
      { connection: (azureConsentReturn ?? githubSetupReturn)!.connectionId },
      "replace",
    );
  }, [azureConsentReturn, githubSetupReturn]);

  const loadRuntimeActivity = useCallback(async (includeFixtures: boolean) => {
    setError(null);
    try {
      const [summaryResult, activityResult] = await Promise.all([
        api.activitySummary(includeFixtures),
        api.activity(includeFixtures),
      ]);
      setActivitySummary(summaryResult);
      setActivities(activityResult.items);
      setIncludeActivityFixtures(includeFixtures);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load runtime activity");
    }
  }, []);

  const includeFixturesFromUrl = navigation.query.fixtures === "1";

  useEffect(() => {
    if (loading || includeActivityFixtures === includeFixturesFromUrl) return;
    void loadRuntimeActivity(includeFixturesFromUrl);
  }, [includeActivityFixtures, includeFixturesFromUrl, loadRuntimeActivity, loading]);

  function toggleActivityFixtures() {
    updateQuery({ fixtures: includeFixturesFromUrl ? null : "1" }, "push");
  }

  function selectConnection(id: string, mode: "push" | "replace" = "push") {
    updateQuery({ connection: id || null, new: null, provider: null }, mode);
  }

  function showConnectionCreate(visible: boolean) {
    updateQuery(
      visible ? { new: "1" } : { new: null, provider: null },
      "push",
    );
  }

  function navigate(next: Page) {
    if (next !== page || Object.keys(navigation.query).length > 0) {
      commitNavigation(next, {}, "push");
    }
    setSidebarOpen(false);
  }

  function openInventory(kind: unknown = "all") {
    commitNavigation("inventory", inventoryQuery(kind), "push");
    setSidebarOpen(false);
  }

  function commitNavigation(
    nextPage: Page,
    query: Readonly<Record<string, string>>,
    mode: "push" | "replace",
    state: object = {},
  ) {
    const nextUrl = navigationUrl(nextPage, query);
    const nextState = { denali: true, page: nextPage, overlayDepth: 0, ...state };
    if (mode === "push") window.history.pushState(nextState, "", nextUrl);
    else window.history.replaceState(nextState, "", nextUrl);
    setNavigation(navigationFromUrl(new URL(nextUrl, window.location.origin)));
  }

  function updateQuery(
    updates: Readonly<Record<string, string | null | undefined>>,
    mode: "push" | "replace" = "push",
  ) {
    const nextQuery = queryWith(navigation.query, updates);
    if (navigationUrl(page, nextQuery) === navigationUrl(page, navigation.query)) return;
    commitNavigation(page, nextQuery, mode, {
      overlayDepth: Number(window.history.state?.overlayDepth) || 0,
      overlayParent: window.history.state?.overlayParent,
    });
  }

  function openDrawer(kind: DrawerKind, id: string) {
    const transition = openDrawerTransition(navigation, window.history.state, kind, id);
    commitNavigation(transition.page, transition.query, transition.mode, transition.state);
  }

  function setDrawerTab(tab: string) {
    const transition = drawerTabTransition(navigation, window.history.state, tab);
    if (transition) commitNavigation(transition.page, transition.query, transition.mode, transition.state);
  }

  function closeDrawer() {
    const transition = closeDrawerTransition(navigation, window.history.state);
    if ("delta" in transition) {
      window.history.go(transition.delta);
      return;
    }
    commitNavigation(transition.page, transition.query, transition.mode, transition.state);
  }

  const filterNavigation: FilterNavigation = {
    values: navigation.query,
    set(key, value, defaultValue = "", mode = "push") {
      updateQuery({ [key]: value === defaultValue ? null : value }, mode);
    },
    clear(keys) {
      updateQuery(Object.fromEntries(keys.map((key) => [key, null])), "push");
    },
  };
  const selectedAssetId =
    navigation.drawer?.kind === "asset" ? navigation.drawer.id : null;
  const selectedFindingId =
    navigation.drawer?.kind === "finding" ? navigation.drawer.id : null;
  const selectedVulnerabilityId =
    navigation.drawer?.kind === "vulnerability" ? navigation.drawer.id : null;
  const selectedIssueId =
    navigation.drawer?.kind === "issue" ? navigation.drawer.id : null;
  const selectedActivityId =
    navigation.drawer?.kind === "activity" ? navigation.drawer.id : null;
  const selectedDetectionId =
    navigation.drawer?.kind === "detection" ? navigation.drawer.id : null;

  return (
    <div className="app-shell">
      <Sidebar page={page} onNavigate={navigate} open={sidebarOpen} />
      {sidebarOpen && <button className="sidebar-scrim" aria-label="Close menu" onClick={() => setSidebarOpen(false)} />}

      <main className="main-shell">
        <Topbar page={page} onMenu={() => setSidebarOpen(true)} onRefresh={loadAll} accountControls={accountControls} />
        <div className="workspace">
          {page === "profile" ? (
            profilePage ?? <ProfileUnavailable />
          ) : error ? (
            <ErrorState message={error} onRetry={loadAll} />
          ) : loading || !summary ? (
            <LoadingState />
          ) : page === "dashboard" ? (
            <Dashboard
              summary={summary}
              assets={assets}
              coverage={coverage}
              issues={issues}
              vulnerabilitySummary={vulnerabilitySummary ?? {
                total: 0,
                by_state: {},
                open_vulnerability_ids: 0,
                open_by_severity: {},
                open_by_fix_state: {},
                open_by_exploit_state: {},
              }}
              activitySummary={activitySummary ?? { total: 0, last_24h: 0, providers: 0, failures: 0, fixture_total: 0, by_category: {} }}
              activities={activities}
              deployments={deployments}
              onOpenAsset={(id) => openDrawer("asset", id)}
              onOpenIssue={(id) => openDrawer("issue", id)}
              onViewInventory={openInventory}
              onViewSources={() => navigate("sources")}
              onNavigate={navigate}
            />
            ) : page === "connections" ? (
            <ConnectionsPage connections={connections} selectedId={navigation.query.connection} showCreate={navigation.query.new === "1" || connections.length === 0} navigation={filterNavigation} onSelect={selectConnection} onShowCreate={showConnectionCreate} onChanged={loadAll} azureConsentReturn={azureConsentReturn} githubSetupReturn={githubSetupReturn} canWrite={canWrite} />
          ) : page === "inventory" ? (
            <Inventory
              assets={assets}
              navigation={filterNavigation}
              onOpenAsset={(id) => openDrawer("asset", id)}
            />
          ) : page === "shadowAi" ? (
            <ShadowAiPage
              assets={assets}
              activities={activities}
              coverage={coverage}
              navigation={filterNavigation}
              onOpenAsset={(id) => openDrawer("asset", id)}
              onOpenActivity={(id) => openDrawer("activity", id)}
            />
          ) : page === "findings" ? (
            <Findings
              summary={findingSummary ?? { total: 0, by_state: {}, open_by_severity: {} }}
              findings={findings}
              navigation={filterNavigation}
              onOpenFinding={(id) => openDrawer("finding", id)}
            />
          ) : page === "vulnerabilities" ? (
            <Vulnerabilities
              summary={vulnerabilitySummary ?? {
                total: 0,
                by_state: {},
                open_vulnerability_ids: 0,
                open_by_severity: {},
                open_by_fix_state: {},
                open_by_exploit_state: {},
              }}
              vulnerabilities={vulnerabilities}
              navigation={filterNavigation}
              onOpenVulnerability={(id) => openDrawer("vulnerability", id)}
            />
          ) : page === "issues" ? (
            <Issues
              summary={issueSummary ?? { total: 0, by_state: {}, open_by_severity: {} }}
              issues={issues}
              evaluations={issueEvaluations}
              navigation={filterNavigation}
              onOpenIssue={(id) => openDrawer("issue", id)}
            />
          ) : page === "codeToCloud" ? (
            <CodeToCloud
              deployments={deployments}
              observations={codeToCloudObservations}
              onOpenAsset={(id) => openDrawer("asset", id)}
              onOpenFinding={(id) => openDrawer("finding", id)}
              onOpenVulnerability={(id) => openDrawer("vulnerability", id)}
            />
          ) : page === "runtime" ? (
            <RuntimeActivityPage
              summary={activitySummary ?? { total: 0, last_24h: 0, providers: 0, failures: 0, fixture_total: 0, by_category: {} }}
              activities={activities}
              includeFixtures={includeActivityFixtures}
              navigation={filterNavigation}
              onToggleFixtures={toggleActivityFixtures}
              onOpenActivity={(id) => openDrawer("activity", id)}
            />
          ) : page === "detections" ? (
            <RuntimeDetectionsPage
              summary={detectionSummary ?? { total: 0, by_state: {}, open_by_severity: {} }}
              detections={detections}
              evaluations={detectionEvaluations}
              coverage={coverage}
              navigation={filterNavigation}
              onOpenDetection={(id) => openDrawer("detection", id)}
            />
          ) : (
            <Sources coverage={coverage} />
          )}
        </div>
      </main>

      {selectedAssetId && (
        <ResourceDrawer
          assetId={selectedAssetId}
          tab={(navigation.drawer?.tab ?? "overview") as DetailTab}
          onTab={setDrawerTab}
          onClose={closeDrawer}
          onOpenAsset={(id) => openDrawer("asset", id)}
          onOpenActivity={(activityId) => {
            openDrawer("activity", activityId);
          }}
          onUpdated={loadAll}
          canWrite={canWrite}
        />
      )}
      {selectedFindingId && (
        <FindingDrawer
          findingId={selectedFindingId}
          tab={(navigation.drawer?.tab ?? "overview") as FindingDetailTab}
          onTab={setDrawerTab}
          onClose={closeDrawer}
        />
      )}
      {selectedIssueId && (
        <IssueDrawer issueId={selectedIssueId} tab={(navigation.drawer?.tab ?? "overview") as IssueDetailTab} onTab={setDrawerTab} onClose={closeDrawer} />
      )}
      {selectedVulnerabilityId && (
        <VulnerabilityDrawer
          vulnerabilityId={selectedVulnerabilityId}
          tab={(navigation.drawer?.tab ?? "overview") as VulnerabilityDetailTab}
          onTab={setDrawerTab}
          onClose={closeDrawer}
          onOpenAsset={(assetId) => {
            openDrawer("asset", assetId);
          }}
        />
      )}
      {selectedActivityId && (
        <RuntimeActivityDrawer
          activityId={selectedActivityId}
          tab={(navigation.drawer?.tab ?? "overview") as "overview" | "evidence"}
          onTab={setDrawerTab}
          onClose={closeDrawer}
          onOpenAsset={(assetId) => {
            openDrawer("asset", assetId);
          }}
        />
      )}
      {selectedDetectionId && (
        <RuntimeDetectionDrawer
          detectionId={selectedDetectionId}
          tab={(navigation.drawer?.tab ?? "overview") as DetectionDetailTab}
          onTab={setDrawerTab}
          onClose={closeDrawer}
          onOpenActivity={(activityId) => {
            openDrawer("activity", activityId);
          }}
          onOpenAsset={(assetId) => {
            openDrawer("asset", assetId);
          }}
        />
      )}
    </div>
  );
}

function Sidebar({ page, onNavigate, open }: { page: Page; onNavigate: (page: Page) => void; open: boolean }) {
  return (
    <aside className={`sidebar ${open ? "sidebar--open" : ""}`}>
      <div className="brand">
        <span className="brand-mark"><Mountain size={24} strokeWidth={2.3} /></span>
        <span><strong>Denali</strong><small>AI Security</small></span>
      </div>

      <nav className="nav-stack" aria-label="Primary navigation">
        <NavButton active={page === "dashboard"} icon={LayoutDashboard} label="Overview" onClick={() => onNavigate("dashboard")} />
        <NavButton active={page === "connections"} icon={CloudCog} label="Connections" onClick={() => onNavigate("connections")} />
        <p className="nav-heading">DISCOVER</p>
        <NavButton active={page === "inventory"} icon={Boxes} label="Inventory" onClick={() => onNavigate("inventory")} />
        <NavButton active={page === "shadowAi"} icon={AppWindow} label={AI_APPLICATION_DISCOVERY_LABEL} onClick={() => onNavigate("shadowAi")} />
        <NavButton active={page === "codeToCloud"} icon={CloudCog} label="Code to cloud" onClick={() => onNavigate("codeToCloud")} />
        <p className="nav-heading">ASSESS</p>
        <NavButton active={page === "findings"} icon={CircleAlert} label="Posture findings" onClick={() => onNavigate("findings")} />
        <NavButton active={page === "vulnerabilities"} icon={Bug} label="Vulnerabilities" onClick={() => onNavigate("vulnerabilities")} />
        <NavButton active={page === "issues"} icon={Network} label="Issues & paths" onClick={() => onNavigate("issues")} />
        <p className="nav-heading">MONITOR</p>
        <NavButton active={page === "runtime"} icon={Activity} label="Runtime activity" onClick={() => onNavigate("runtime")} />
        <NavButton active={page === "detections"} icon={Gauge} label="Detections" onClick={() => onNavigate("detections")} />
        <p className="nav-heading">DATA</p>
        <NavButton active={page === "sources"} icon={Waypoints} label="Sources & coverage" onClick={() => onNavigate("sources")} />
        <p className="nav-heading">ACCOUNT</p>
        <NavButton active={page === "profile"} icon={UserRound} label="Profile & organization" onClick={() => onNavigate("profile")} />
      </nav>

      <div className="sidebar-footer">
        <div className="preview-chip"><Sparkles size={14} /> Community Edition</div>
        <p>Evidence-led AI security</p>
        <span className="open-source-label"><FileCode2 size={15} /> Apache 2.0 · Open source</span>
      </div>
    </aside>
  );
}

function NavButton({
  active = false,
  icon: Icon,
  label,
  badge,
  disabled = false,
  onClick,
}: {
  active?: boolean;
  icon: LucideIcon;
  label: string;
  badge?: string;
  disabled?: boolean;
  onClick?: () => void;
}) {
  return (
    <button className={`nav-button ${active ? "is-active" : ""}`} disabled={disabled} onClick={onClick}>
      <Icon size={18} />
      <span>{label}</span>
      {badge && <small>{badge}</small>}
    </button>
  );
}

function Topbar({ page, onMenu, onRefresh, accountControls }: { page: Page; onMenu: () => void; onRefresh: () => void; accountControls?: ReactNode }) {
  const titles: Record<Page, { eyebrow: string; title: string }> = {
    dashboard: { eyebrow: "Command center", title: "Denali Brief" },
    connections: { eyebrow: "Setup", title: "Connections" },
    inventory: { eyebrow: "Discovery", title: "AI inventory" },
    shadowAi: { eyebrow: "Discovery", title: AI_APPLICATION_DISCOVERY_LABEL },
    findings: { eyebrow: "Posture", title: "AI configuration findings" },
    vulnerabilities: { eyebrow: "Exposure", title: "AI vulnerabilities" },
    issues: { eyebrow: "Correlation", title: "AI issues & paths" },
    codeToCloud: { eyebrow: "Lineage", title: "Code to cloud" },
    runtime: { eyebrow: "Runtime", title: "AI runtime activity" },
    detections: { eyebrow: "Behavior", title: "Runtime detections" },
    sources: { eyebrow: "Data confidence", title: "Sources & coverage" },
    profile: { eyebrow: "Workspace", title: "Profile & organization" },
  };
  const content = titles[page];
  return (
    <header className="topbar">
      <button className="mobile-menu" onClick={onMenu} aria-label="Open menu"><Menu /></button>
      <div><span>{content.eyebrow}</span><h1>{content.title}</h1></div>
      <div className="topbar-actions">
        <button className="icon-button" title="Refresh data" onClick={() => void onRefresh()}><RefreshCw size={17} /></button>
        <div className="environment"><span /> Evidence current</div>
        <div className="edition-badge">Community</div>
        {accountControls && <div className="account-controls">{accountControls}</div>}
      </div>
    </header>
  );
}

function ProfileUnavailable() {
  return (
    <div className="state-page">
      <UserRound />
      <h2>Hosted profile unavailable</h2>
      <p>Profile and organization management is available when Denali runs with Clerk.</p>
    </div>
  );
}

function Dashboard({
  summary,
  assets,
  coverage,
  issues,
  vulnerabilitySummary,
  activitySummary,
  activities,
  deployments,
  onOpenAsset,
  onOpenIssue,
  onViewInventory,
  onViewSources,
  onNavigate,
}: {
  summary: Summary;
  assets: Asset[];
  coverage: Coverage[];
  issues: Issue[];
  vulnerabilitySummary: VulnerabilitySummary;
  activitySummary: RuntimeActivitySummary;
  activities: RuntimeActivity[];
  deployments: CodeToCloudDeployment[];
  onOpenAsset: (id: string) => void;
  onOpenIssue: (id: string) => void;
  onViewInventory: (kind?: string) => void;
  onViewSources: () => void;
  onNavigate: (page: Page) => void;
}) {
  const unreviewedWorkloads = assets.filter(
    (asset) => asset.kind === "ai_workload" && asset.governance_status === "unreviewed",
  ).length;
  const provenDeployments = deployments.length;
  const complete = coverage.filter((item) => item.state === "complete").length;
  const allComplete = coverage.length > 0 && complete === coverage.length;
  const incompleteCoverage = coverage.length - complete;
  const kinds = Object.entries(summary.by_kind).sort(([, left], [, right]) => right - left);
  const severityRank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, informational: 1, unknown: 0 };
  const priorityIssue = [...issues]
    .filter((issue) => issue.state === "open")
    .sort((left, right) => (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0) || right.confidence - left.confidence)[0];
  const criticalVulnerabilityOccurrences = vulnerabilitySummary.open_by_severity.critical ?? 0;
  const fixableVulnerabilityOccurrences = vulnerabilitySummary.open_by_fix_state.fixed ?? 0;
  const timestamps = [
    ...assets.map((asset) => asset.last_seen_at),
    ...coverage.map((item) => item.collected_at),
    ...issues.map((issue) => issue.last_seen_at),
    ...activities.map((activity) => activity.occurred_at),
  ].filter(Boolean).sort();
  const freshest = timestamps.at(-1);

  return (
    <div className="page-stack dashboard-page">
      <section className="brief-intro">
        <div>
          <span className="eyebrow">EVIDENCE BRIEF</span>
          <h2>Your AI estate, explained.</h2>
          <p>A prioritized operating picture built only from retained inventory, posture, runtime, and correlation evidence.</p>
        </div>
      <div className="brief-freshness">
        <Clock3 size={16} />
        <span>Latest evidence</span>
        <strong>{freshest ? formatTime(freshest) : "Not collected"}</strong>
      </div>
      </section>

      <GoldenPath deployments={deployments} onOpen={() => onNavigate("codeToCloud")} />

      <section className="command-grid">
        <section className="denali-brief">
          <div className="brief-header">
            <div><span className="brief-label"><Sparkles size={15} /> DENALI BRIEF</span><h3>What deserves attention now</h3></div>
            <span className="deterministic-badge"><ShieldCheck size={14} /> Evidence-backed</span>
          </div>
          <div className="brief-priorities">
            <button className="brief-priority" onClick={() => priorityIssue ? onOpenIssue(priorityIssue.id) : onNavigate("issues")}>
              <span className="priority-number">01</span>
              <span className="priority-copy">
                <small>{priorityIssue ? `${priorityIssue.severity.toUpperCase()} CORRELATED ISSUE` : "CORRELATION"}</small>
                <strong>{priorityIssue?.title ?? "No open correlated issue is currently retained"}</strong>
                <span>{priorityIssue ? `${Math.round(priorityIssue.confidence * 100)}% confidence · ${priorityIssue.finding_count + priorityIssue.detection_count + priorityIssue.activity_count} linked signals` : "No issue has crossed a configured correlation threshold."}</span>
              </span>
              <ChevronRight size={19} />
            </button>
            <button className="brief-priority" onClick={() => onViewInventory("ai_workload")}>
              <span className="priority-number">02</span>
              <span className="priority-copy">
                <small>AI WORKLOAD GOVERNANCE</small>
                <strong>{unreviewedWorkloads === 0 ? "No observed AI workloads await review" : `${unreviewedWorkloads} observed AI workload${unreviewedWorkloads === 1 ? "" : "s"} await review`}</strong>
                <span>Observed in cloud control planes · governance decisions remain with your team</span>
              </span>
              <ChevronRight size={19} />
            </button>
            <button className="brief-priority" onClick={() => onNavigate("vulnerabilities")}>
              <span className="priority-number">03</span>
              <span className="priority-copy">
                <small>AI STACK EXPOSURE</small>
                <strong>{vulnerabilitySummary.open_vulnerability_ids} distinct open vulnerabilities</strong>
                <span>{criticalVulnerabilityOccurrences} critical occurrences · {fixableVulnerabilityOccurrences} with a scanner-provided fix</span>
              </span>
              <ChevronRight size={19} />
            </button>
          </div>
        </section>

        <aside className="panel evidence-rail">
          <div className="evidence-rail-header">
            <span className="eyebrow">EVIDENCE BOUNDARY</span>
            <h3>What the data can support</h3>
            <p>Verified observations stay separate from decisions Denali cannot make for you.</p>
          </div>
          <div className={`evidence-health ${allComplete ? "complete" : "attention"}`}>
            {allComplete ? <CircleCheck size={19} /> : <CircleAlert size={19} />}
            <span><strong>{complete}/{coverage.length} collection planes complete</strong><small>{allComplete ? "Declared coverage is current" : "Some declared coverage is incomplete"}</small></span>
          </div>
          <div className="evidence-boundary-list">
            <button className="evidence-boundary-item proven" onClick={() => onNavigate("codeToCloud")}>
              <span>PROVEN</span>
              <strong>{provenDeployments} proven deployment link{provenDeployments === 1 ? "" : "s"}</strong>
              <small>Exact source declaration + independently observed cloud identity</small>
              <ChevronRight size={16} />
            </button>
            <button className="evidence-boundary-item undecided" onClick={() => onViewInventory("ai_workload")}>
              <span>NEEDS DECISION</span>
              <strong>{unreviewedWorkloads} AI workload review{unreviewedWorkloads === 1 ? "" : "s"}</strong>
              <small>{incompleteCoverage === 0 ? "No declared collection gap" : `${incompleteCoverage} incomplete collection plane${incompleteCoverage === 1 ? "" : "s"}`}</small>
              <ChevronRight size={16} />
            </button>
          </div>
          <div className="evidence-rail-actions">
            <button onClick={onViewSources}>Inspect evidence sources <ChevronRight size={15} /></button>
            <button onClick={() => onViewInventory("ai_workload")}>Review workload governance <ChevronRight size={15} /></button>
          </div>
        </aside>
      </section>

      <section className="metric-grid">
        <MetricCard icon={Boxes} color="coral" label="Known resources" value={summary.total} detail={`${kinds.length} normalized resource types`} onClick={() => onViewInventory()} />
        <MetricCard icon={CircleHelp} color="amber" label="AI workloads to review" value={unreviewedWorkloads} detail="Governance state not yet decided" onClick={() => onViewInventory("ai_workload")} />
        <MetricCard icon={ShieldCheck} color="green" label="Proven deployments" value={provenDeployments} detail="Exact source + cloud identity" onClick={() => onNavigate("codeToCloud")} />
        <MetricCard icon={Activity} color="blue" label="Runtime observations" value={activitySummary.total} detail={`${activitySummary.last_24h} observed in the last 24 hours`} onClick={() => onNavigate("runtime")} />
      </section>

      <section className="dashboard-grid">
        <div className="panel inventory-map-panel">
          <PanelHeader eyebrow="VISIBILITY" title="Your AI system" action="Explore inventory" onAction={() => onViewInventory()} />
          <div className="composition-list">
            {kinds.map(([kind, count]) => {
              const itemMeta = meta(kind);
              const Icon = itemMeta.icon;
              return (
                <button key={kind} className="composition-row" onClick={() => onViewInventory(kind)}>
                  <span className={`asset-icon ${itemMeta.color}`}><Icon size={18} /></span>
                  <span className="composition-name"><strong>{itemMeta.plural}</strong><small>{count === 1 ? "1 discovered resource" : `${count} discovered resources`}</small></span>
                  <span className="composition-bar"><i style={{ width: `${Math.max(10, (count / summary.total) * 100)}%` }} /></span>
                  <b>{count}</b><ChevronRight size={16} />
                </button>
              );
            })}
          </div>
        </div>

        <div className="right-stack">
          <div className="panel coverage-panel">
            <PanelHeader eyebrow="CONFIDENCE" title="Collection health" action="View sources" onAction={onViewSources} />
            <div className={`coverage-callout ${allComplete ? "complete" : "attention"}`}>
              {allComplete ? <CircleCheck /> : <CircleAlert />}
              <div><strong>{allComplete ? "Coverage is complete" : "Coverage needs attention"}</strong><span>{complete} of {coverage.length} declared collection planes completed</span></div>
            </div>
            {coverage.slice(0, 3).map((item) => <CoverageRow key={`${item.connector_id}-${item.plane}`} item={item} />)}
          </div>

          <div className="panel recent-panel">
            <PanelHeader eyebrow="RECENTLY SEEN" title="Inventory highlights" />
            {assets.slice(0, 4).map((asset) => <AssetMiniRow key={asset.id} asset={asset} onClick={() => onOpenAsset(asset.id)} />)}
          </div>
        </div>
      </section>
      <p className="fixture-note"><CircleHelp size={15} /> Counts describe retained evidence and declared collection planes. Absence of evidence is never presented as evidence of absence.</p>
    </div>
  );
}

function GoldenPath({
  deployments,
  onOpen,
}: {
  deployments: CodeToCloudDeployment[];
  onOpen: () => void;
}) {
  const ordered = [...deployments].sort((left, right) => {
    const providerOrder = Number(!left.workload_natural_key.startsWith("arn:aws:")) -
      Number(!right.workload_natural_key.startsWith("arn:aws:"));
    return providerOrder || left.workload_natural_key.localeCompare(right.workload_natural_key);
  });
  return (
    <section className="golden-path-panel">
      <div className="golden-path-head">
        <div>
          <span className="eyebrow"><Sparkles size={13} /> GOLDEN PATH</span>
          <h3>Two applications. Two clouds. One reviewable story.</h3>
          <p>Start with source, follow an exact deployment declaration, and land on a workload independently observed in its cloud control plane.</p>
        </div>
        <button onClick={onOpen}>Open code-to-cloud <ChevronRight size={16} /></button>
      </div>
      <div className="golden-path-apps">
        {ordered.map((deployment, index) => {
          const provider = deployment.workload_natural_key.startsWith("arn:aws:") ? "AWS" : "GCP";
          const repositorySlug = deployment.repository_natural_key.split("/").at(-1) ?? deployment.repository_name;
          const rawWorkloadName = deployment.workload_natural_key.split(/[/:]/).at(-1) ?? deployment.workload_name;
          const applicationName = deployment.workload_name !== rawWorkloadName
            ? deployment.workload_name
            : titleCase(repositorySlug.replaceAll("-", " "));
          const location = provider === "AWS"
            ? deployment.workload_natural_key.split(":")[3]
            : deployment.workload_natural_key.match(/\/locations\/([^/]+)/)?.[1];
          return (
            <button className="golden-path-app" key={deployment.id} onClick={onOpen}>
              <span className={`golden-path-number ${provider.toLowerCase()}`}>{String(index + 1).padStart(2, "0")}</span>
              <span className="golden-path-copy">
                <small>{provider} · {location ?? "cloud runtime"}</small>
                <strong>{applicationName}</strong>
                <code>{deployment.repository_natural_key}</code>
              </span>
              <span className="golden-path-link"><GitBranch size={15} /><i /><ShieldCheck size={15} /></span>
              <span className="golden-path-runtime">
                <small>PROVEN RUNTIME</small>
                <strong>{deployment.workload_name}</strong>
                <em>{deployment.code_findings.length} source finding{deployment.code_findings.length === 1 ? "" : "s"} · {deployment.identity ? "identity observed" : "identity unavailable"}</em>
              </span>
              <ChevronRight size={18} />
            </button>
          );
        })}
      </div>
      <div className="golden-path-proof"><ShieldCheck size={16} /><span><strong>{deployments.length} exact source-to-runtime links</strong> retained from immutable GitHub revisions and independent AWS/GCP observations.</span></div>
    </section>
  );
}

function MetricCard({ icon: Icon, color, label, value, detail, onClick }: { icon: LucideIcon; color: string; label: string; value: string | number; detail: string; onClick?: () => void }) {
  return (
    <button className="metric-card" type="button" onClick={onClick} aria-label={`${label}: ${value}. ${detail}`}>
      <span className={`metric-icon ${color}`}><Icon /></span>
      <div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
      <ChevronRight className="metric-chevron" size={18} aria-hidden="true" />
    </button>
  );
}

function PanelHeader({ eyebrow, title, action, onAction }: { eyebrow: string; title: string; action?: string; onAction?: () => void }) {
  return <div className="panel-header"><div><span>{eyebrow}</span><h3>{title}</h3></div>{action && <button onClick={onAction}>{action}<ChevronRight size={15} /></button>}</div>;
}

function CoverageRow({ item }: { item: Coverage }) {
  return <div className="coverage-row"><span className={`status-dot ${item.state}`} /><div><strong>{titleCase(item.plane)}</strong><small>{item.connector_id} · {item.scope}</small></div><span className={`state-badge ${item.state}`}>{titleCase(item.state)}</span></div>;
}

function AssetMiniRow({ asset, onClick }: { asset: Asset; onClick: () => void }) {
  const itemMeta = meta(asset.kind); const Icon = itemMeta.icon;
  return <button className="asset-mini-row" onClick={onClick}><span className={`asset-icon ${itemMeta.color}`}><Icon size={17} /></span><span><strong>{asset.display_name ?? shortKey(asset.natural_key)}</strong><small>{itemMeta.label} · {asset.assertion_type?.replaceAll("_", " ")}</small></span><ChevronRight size={16} /></button>;
}

function Inventory({ assets, navigation, onOpenAsset }: { assets: Asset[]; navigation: FilterNavigation; onOpenAsset: (id: string) => void }) {
  const search = navigation.values.q ?? "";
  const kind = navigation.values.kind ?? "all";
  const governance = navigation.values.governance ?? "all";

  const filtered = useMemo(() => assets.filter((asset) => {
    const haystack = `${asset.display_name ?? ""} ${asset.natural_key} ${asset.kind}`.toLowerCase();
    return haystack.includes(search.toLowerCase()) && (kind === "all" || asset.kind === kind) && (governance === "all" || asset.governance_status === governance);
  }), [assets, governance, kind, search]);

  const kinds = [...new Set(assets.map((asset) => asset.kind))].sort();
  return (
    <div className="page-stack">
      <section className="page-intro"><div><span className="eyebrow">CANONICAL INVENTORY</span><h2>Every AI resource, one trustworthy record.</h2><p>Search normalized inventory while preserving every source assertion and its evidence.</p></div><div className="result-count"><strong>{filtered.length}</strong><span>active resources</span></div></section>
      <section className="panel inventory-panel">
        <div className="filterbar">
          <label className="search-field"><Search size={18} /><input value={search} onChange={(event) => navigation.set("q", event.target.value, "", "replace")} placeholder="Search name, key, or type…" /></label>
          <label className="select-field"><ListFilter size={16} /><select value={kind} onChange={(event) => navigation.set("kind", event.target.value, "all")}><option value="all">All resource types</option>{kinds.map((item) => <option key={item} value={item}>{meta(item).plural}</option>)}</select></label>
          <label className="select-field"><Filter size={16} /><select value={governance} onChange={(event) => navigation.set("governance", event.target.value, "all")}><option value="all">All governance</option><option value="approved">Approved</option><option value="unreviewed">Unreviewed</option><option value="unwanted">Unwanted</option></select></label>
          {(search || kind !== "all" || governance !== "all") && <button className="clear-button" onClick={() => navigation.clear(["q", "kind", "governance"])}>Clear filters</button>}
        </div>
        <div className="inventory-table" role="table" aria-label="AI inventory">
          <div className="inventory-table-head" role="row"><span>Resource</span><span>Type</span><span>Verification</span><span>Governance</span><span>Last seen</span><span /></div>
          {filtered.map((asset) => <AssetTableRow key={asset.id} asset={asset} onClick={() => onOpenAsset(asset.id)} />)}
          {filtered.length === 0 && <div className="empty-state"><Search /><strong>No inventory matches these filters</strong><span>Try another name or broaden the selected resource type.</span></div>}
        </div>
      </section>
    </div>
  );
}

function AssetTableRow({ asset, onClick }: { asset: Asset; onClick: () => void }) {
  const itemMeta = meta(asset.kind); const Icon = itemMeta.icon;
  return <button className="inventory-table-row" role="row" onClick={onClick}>
    <span className="resource-cell"><span className={`asset-icon ${itemMeta.color}`}><Icon size={18} /></span><span><strong>{asset.display_name ?? shortKey(asset.natural_key)}</strong><small>{asset.natural_key}</small></span></span>
    <span>{itemMeta.label}</span>
    <span><span className="verification"><Check size={13} />{titleCase(asset.assertion_type ?? "unknown")}</span><small className="confidence">{Math.round((asset.confidence ?? 0) * 100)}% confidence</small></span>
    <span><span className={`governance-badge ${asset.governance_status}`}>{titleCase(asset.governance_status)}</span></span>
    <span>{formatTime(asset.last_seen_at)}</span><span><ChevronRight size={17} /></span>
  </button>;
}

const SEVERITY_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "informational", "unknown"];

function Findings({
  summary,
  findings,
  navigation,
  onOpenFinding,
}: {
  summary: FindingSummary;
  findings: Finding[];
  navigation: FilterNavigation;
  onOpenFinding: (id: string) => void;
}) {
  const search = navigation.values.q ?? "";
  const severity = navigation.values.severity ?? "all";
  const state = navigation.values.state ?? "open";
  const filtered = useMemo(
    () =>
      findings.filter((finding) => {
        const haystack = `${finding.title} ${finding.rule_uid} ${finding.connector_id} ${finding.class_name}`.toLowerCase();
        return (
          haystack.includes(search.toLowerCase()) &&
          (severity === "all" || finding.severity === severity) &&
          (state === "all" || finding.state === state)
        );
      }),
    [findings, search, severity, state],
  );

  return <div className="page-stack findings-page">
    <section className="page-intro"><div><span className="eyebrow">ATOMIC, EVIDENCE-BEARING FACTS</span><h2>AI configuration findings</h2><p>Provider-neutral posture findings from Prowler, OCSF producers, and Denali-native checks—kept separate from inventory claims.</p></div><div className="result-count"><strong>{summary.by_state.open ?? 0}</strong><span>open findings</span></div></section>
    <section className="finding-metric-grid">
      {SEVERITY_ORDER.slice(0, 4).map((item) => <FindingMetric key={item} severity={item} count={summary.open_by_severity[item] ?? 0} />)}
    </section>
    <section className="panel findings-panel">
      <div className="filterbar">
        <label className="search-field"><Search size={18} /><input value={search} onChange={(event) => navigation.set("q", event.target.value, "", "replace")} placeholder="Search finding, rule, class, or source…" /></label>
        <label className="select-field"><CircleAlert size={16} /><select value={severity} onChange={(event) => navigation.set("severity", event.target.value, "all")}><option value="all">All severities</option>{SEVERITY_ORDER.map((item) => <option key={item} value={item}>{titleCase(item)}</option>)}</select></label>
        <label className="select-field"><ListFilter size={16} /><select value={state} onChange={(event) => navigation.set("state", event.target.value, "open")}><option value="all">All states</option><option value="open">Open</option><option value="unknown">Unknown</option><option value="suppressed">Suppressed</option><option value="resolved">Resolved</option></select></label>
        {(search || severity !== "all" || state !== "open") && <button className="clear-button" onClick={() => navigation.clear(["q", "severity", "state"])}>Reset</button>}
      </div>
      <div className="findings-table" role="table" aria-label="AI configuration findings">
        <div className="findings-table-head" role="row"><span>Finding</span><span>Severity</span><span>State</span><span>Affected</span><span>Source</span><span>Last seen</span><span /></div>
        {filtered.map((finding) => <FindingTableRow key={finding.id} finding={finding} onClick={() => onOpenFinding(finding.id)} />)}
        {filtered.length === 0 && <div className="empty-state"><ShieldCheck /><strong>{findings.length === 0 ? "No findings have been imported" : "No findings match these filters"}</strong><span>{findings.length === 0 ? "Import a Prowler JSON-OCSF report or run the transparent demo seed." : "Reset the filters or include resolved findings."}</span></div>}
      </div>
    </section>
    <p className="fixture-note"><CircleHelp size={15} /> Findings are evaluated conditions. Resource references do not create inventory assets or graph edges.</p>
  </div>;
}

function FindingMetric({ severity, count }: { severity: FindingSeverity; count: number }) {
  return <div className={`finding-metric severity-${severity}`}><span className="severity-mark"><CircleAlert /></span><div><span>{titleCase(severity)}</span><strong>{count}</strong><small>open {count === 1 ? "finding" : "findings"}</small></div></div>;
}

function FindingTableRow({ finding, onClick }: { finding: Finding; onClick: () => void }) {
  return <button className="findings-table-row" role="row" onClick={onClick}>
    <span className="finding-title-cell"><span className={`finding-icon severity-${finding.severity}`}><CircleAlert size={18} /></span><span><strong>{finding.title}</strong><small>{finding.rule_uid} · {finding.class_name}</small></span></span>
    <span><span className={`severity-badge ${finding.severity}`}>{titleCase(finding.severity)}</span></span>
    <span><span className={`finding-state ${finding.state}`}>{titleCase(finding.state)}</span></span>
    <span>{finding.resource_count} {finding.resource_count === 1 ? "resource" : "resources"}</span>
    <span className="finding-source"><strong>{finding.connector_id}</strong><small>{finding.connection_id}</small></span>
    <span>{formatTime(finding.last_seen_at)}</span><span><ChevronRight size={17} /></span>
  </button>;
}

function FindingDrawer({ findingId, tab, onTab, onClose }: { findingId: string; tab: FindingDetailTab; onTab: (tab: string) => void; onClose: () => void }) {
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDetail(null); setError(null);
    api.finding(findingId).then(setDetail).catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load finding"));
  }, [findingId]);

  return <div className="drawer-layer"><button className="drawer-scrim" onClick={onClose} aria-label="Close finding detail" /><aside className="resource-drawer finding-drawer" aria-label="Finding detail">
    {!detail && !error ? <LoadingState compact /> : error ? <ErrorState message={error} subject="finding" /> : detail && <>
      <div className="drawer-header finding-drawer-header"><button className="drawer-close" onClick={onClose}><X /></button><span className={`finding-icon large severity-${detail.severity}`}><CircleAlert /></span><div><span>{detail.class_name}</span><h2>{detail.title}</h2><p>{detail.rule_uid} · {detail.connector_id}</p></div><span className={`severity-badge ${detail.severity}`}>{titleCase(detail.severity)}</span></div>
      <div className="finding-summary-strip"><span className={`finding-state ${detail.state}`}>{titleCase(detail.state)}</span><span><strong>{detail.resources.length}</strong> affected {detail.resources.length === 1 ? "resource" : "resources"}</span><span><strong>{Object.keys(detail.compliance).length}</strong> frameworks</span><span>Last seen <strong>{formatTime(detail.last_seen_at)}</strong></span></div>
      <div className="drawer-tabs">{(["overview", "evidence", "history"] as const).map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => onTab(item)}>{titleCase(item)}{item === "history" && <small>{detail.observations.length}</small>}</button>)}</div>
      <div className="drawer-content">
        {tab === "overview" ? <FindingOverview detail={detail} /> : tab === "evidence" ? <FindingEvidence detail={detail} /> : <FindingHistory detail={detail} />}
      </div>
    </>}
  </aside></div>;
}

function FindingOverview({ detail }: { detail: FindingDetail }) {
  return <div className="detail-stack">
    <div className="finding-narrative"><span>WHAT DENALI OBSERVED</span><p>{detail.description ?? "The source did not provide a description."}</p></div>
    {detail.risk && <DetailSection title="Risk and impact"><p className="finding-copy">{detail.risk}</p></DetailSection>}
    {detail.remediation && <DetailSection title="Recommended remediation"><p className="finding-copy">{detail.remediation}</p>{detail.remediation_references.length > 0 && <div className="reference-list">{detail.remediation_references.map((reference) => <a key={reference} href={reference} target="_blank" rel="noreferrer"><Link2 />{reference}</a>)}</div>}</DetailSection>}
    <DetailSection title="Finding properties"><div className="property-grid"><Property label="Rule" value={detail.rule_uid} mono /><Property label="Evaluation" value={titleCase(detail.evaluation_result)} /><Property label="First seen" value={formatTime(detail.first_seen_at)} /><Property label="Last changed" value={formatTime(detail.last_changed_at)} /><Property label="Source" value={detail.connector_id} /><Property label="Connection" value={detail.connection_id} /><Property label="OCSF class" value={`${detail.class_name} (${detail.class_uid})`} /><Property label="Scope" value={detail.scope_key} mono /></div></DetailSection>
    <DetailSection title="Affected resources"><div className="affected-list">{detail.resources.map((resource) => <div key={resource.uid}><span className="affected-icon"><Boxes /></span><span><strong>{resource.name ?? shortKey(resource.uid)}</strong><small>{resource.resource_type ?? "Resource"} · {resource.provider ?? "Unknown provider"}</small><code>{resource.uid}</code></span>{resource.region && <em>{resource.region}</em>}</div>)}</div></DetailSection>
    {Object.keys(detail.compliance).length > 0 && <DetailSection title="Related frameworks"><div className="compliance-list">{Object.entries(detail.compliance).map(([framework, controls]) => <div key={framework}><strong>{framework}</strong><span>{controls.map((control) => <i key={control}>{control}</i>)}</span></div>)}</div></DetailSection>}
  </div>;
}

function FindingEvidence({ detail }: { detail: FindingDetail }) {
  return <div className="detail-stack"><div className="evidence-principle"><ShieldCheck /><div><strong>Source evidence remains intact</strong><p>Denali normalizes the security fact without copying arbitrary OCSF resource data or turning references into inventory.</p></div></div><DetailSection title="Evidence"><div className="evidence-card"><Property label="Source type" value={detail.evidence.source_type} /><Property label="Observed at" value={formatTime(detail.evidence.observed_at)} /><Property label="Locator" value={detail.evidence.locator} mono /><Property label="Source UID" value={detail.source_uid} mono /><details><summary>Normalized evidence payload</summary><pre>{JSON.stringify(detail.evidence.payload, null, 2)}</pre></details></div></DetailSection>{Object.keys(detail.attributes).length > 0 && <DetailSection title="Source metadata"><div className="attribute-list">{Object.entries(detail.attributes).map(([key, value]) => <div key={key}><span>{titleCase(key)}</span><strong>{String(value)}</strong></div>)}</div></DetailSection>}</div>;
}

function FindingHistory({ detail }: { detail: FindingDetail }) {
  const groups = useMemo(() => detail.observations.reduce<Array<{
    latest: FindingDetail["observations"][number];
    earliest: FindingDetail["observations"][number];
    count: number;
    key: string;
  }>>((result, observation) => {
    const semanticKey = [observation.evaluation_result, observation.severity, observation.state, observation.scope_key].join("|");
    const previous = result.at(-1);
    if (previous?.key === semanticKey) {
      previous.earliest = observation;
      previous.count += 1;
    } else {
      result.push({ latest: observation, earliest: observation, count: 1, key: semanticKey });
    }
    return result;
  }, []), [detail.observations]);

  return <div className="detail-stack"><div className="history-intro"><Clock3 /><div><strong>Observation history</strong><p>Repeated collections are grouped unless the finding's security meaning changes.</p></div></div><div className="finding-history">{groups.map((group) => <div key={`${group.key}-${group.latest.collected_at}`}><span className={`history-dot ${group.latest.state}`} /><div><strong>{titleCase(group.latest.evaluation_result)} · {titleCase(group.latest.severity)}</strong><small>{formatTime(group.latest.collected_at)}{group.count > 1 ? ` · observed ${group.count} times since ${formatTime(group.earliest.collected_at)}` : ""}</small><p>{titleCase(group.latest.state)} in {group.latest.scope_key}</p></div></div>)}</div></div>;
}

function Vulnerabilities({
  summary,
  vulnerabilities,
  navigation,
  onOpenVulnerability,
}: {
  summary: VulnerabilitySummary;
  vulnerabilities: Vulnerability[];
  navigation: FilterNavigation;
  onOpenVulnerability: (id: string) => void;
}) {
  const search = navigation.values.q ?? "";
  const severity = navigation.values.severity ?? "all";
  const state = navigation.values.state ?? "open";
  const fix = navigation.values.fix ?? "all";
  const filtered = useMemo(() => vulnerabilities.filter((item) => {
    const component = item.component_name ?? item.component_natural_key;
    const haystack = `${item.vulnerability_id} ${item.title ?? ""} ${component} ${item.scanner}`.toLowerCase();
    return haystack.includes(search.toLowerCase()) &&
      (severity === "all" || item.severity === severity) &&
      (state === "all" || item.state === state) &&
      (fix === "all" || item.fix_state === fix);
  }), [fix, search, severity, state, vulnerabilities]);
  const fixable = summary.open_by_fix_state.fixed ?? 0;
  const exploited = (summary.open_by_exploit_state.known_exploited ?? 0) +
    (summary.open_by_exploit_state.public_exploit ?? 0);

  return <div className="page-stack vulnerabilities-page">
    <section className="page-intro"><div><span className="eyebrow">SBOM-FIRST EXPOSURE</span><h2>Vulnerabilities in the AI stack</h2><p>Scanner-neutral vulnerabilities mapped to exact component occurrences and the AI workloads that contain them.</p></div><div className="result-count"><strong>{summary.open_vulnerability_ids}</strong><span>distinct open vulnerabilities</span><small>{summary.by_state.open ?? 0} affected component occurrences</small></div></section>
    <section className="vulnerability-metric-grid">
      <VulnerabilityMetric icon={CircleAlert} tone="critical" label="Critical" value={summary.open_by_severity.critical ?? 0} detail="affected occurrences" />
      <VulnerabilityMetric icon={CircleAlert} tone="high" label="High" value={summary.open_by_severity.high ?? 0} detail="affected occurrences" />
      <VulnerabilityMetric icon={ShieldCheck} tone="fixable" label="Fix available" value={fixable} detail="affected occurrences" />
      <VulnerabilityMetric icon={Bug} tone="exploit" label="Exploit evidence" value={exploited} detail="affected occurrences" />
    </section>
    <section className="panel vulnerabilities-panel">
      <div className="filterbar">
        <label className="search-field"><Search size={18} /><input value={search} onChange={(event) => navigation.set("q", event.target.value, "", "replace")} placeholder="Search CVE, component, or scanner…" /></label>
        <label className="select-field"><CircleAlert size={16} /><select value={severity} onChange={(event) => navigation.set("severity", event.target.value, "all")}><option value="all">All severities</option>{SEVERITY_ORDER.map((item) => <option key={item} value={item}>{titleCase(item)}</option>)}</select></label>
        <label className="select-field"><ListFilter size={16} /><select value={state} onChange={(event) => navigation.set("state", event.target.value, "open")}><option value="all">All states</option><option value="open">Open</option><option value="unknown">Unknown</option><option value="suppressed">Suppressed</option><option value="resolved">Resolved</option></select></label>
        <label className="select-field"><ShieldCheck size={16} /><select value={fix} onChange={(event) => navigation.set("fix", event.target.value, "all")}><option value="all">Any fix state</option><option value="fixed">Fix available</option><option value="not_fixed">No fix</option><option value="wont_fix">Won't fix</option><option value="unknown">Unknown fix state</option></select></label>
        {(search || severity !== "all" || state !== "open" || fix !== "all") && <button className="clear-button" onClick={() => navigation.clear(["q", "severity", "state", "fix"])}>Reset</button>}
      </div>
      <div className="vulnerabilities-table" role="table" aria-label="AI vulnerabilities">
        <div className="vulnerabilities-table-head" role="row"><span>Vulnerability</span><span>Severity</span><span>Component</span><span>Fix</span><span>Scanner</span><span>Last seen</span><span /></div>
        {filtered.map((item) => <VulnerabilityTableRow key={item.id} item={item} onClick={() => onOpenVulnerability(item.id)} />)}
        {filtered.length === 0 && <div className="empty-state"><ShieldCheck /><strong>{vulnerabilities.length === 0 ? "No vulnerability reports have been imported" : "No vulnerabilities match these filters"}</strong><span>{vulnerabilities.length === 0 ? "Import a Syft SBOM and Grype JSON report, or run the transparent demo seed." : "Reset the filters or include resolved vulnerabilities."}</span></div>}
      </div>
    </section>
    <p className="fixture-note"><ShieldCheck size={15} /> A package match is evidence, not certainty. Scanner match method, Denali-derived confidence, database version, and component correlation stay visible.</p>
  </div>;
}

function VulnerabilityMetric({ icon: Icon, tone, label, value, detail }: { icon: LucideIcon; tone: string; label: string; value: number; detail: string }) {
  return <div className={`vulnerability-metric ${tone}`}><span><Icon /></span><div><small>{label}</small><strong>{value}</strong><em>{detail}</em></div></div>;
}

function VulnerabilityTableRow({ item, onClick }: { item: Vulnerability; onClick: () => void }) {
  const component = item.component_attributes?.component as Record<string, unknown> | undefined;
  const componentName = item.component_name ?? "Uncorrelated component";
  const version = typeof component?.version === "string" ? component.version : null;
  return <button className="vulnerabilities-table-row" role="row" onClick={onClick}>
    <span className="vulnerability-title-cell"><span className={`finding-icon severity-${item.severity}`}><Bug size={18} /></span><span><strong>{item.vulnerability_id}</strong><small>{item.exploit_state === "unknown" ? "Exploit status unknown" : titleCase(item.exploit_state)} · {item.source_count} {item.source_count === 1 ? "source" : "sources"}</small></span></span>
    <span><span className={`severity-badge ${item.severity}`}>{titleCase(item.severity)}</span></span>
    <span className="component-cell"><strong>{componentName}</strong><small>{version ? `Version ${version}` : item.component_correlated ? "Version retained in inventory" : "Inventory not yet correlated"}</small></span>
    <span><span className={`fix-badge ${item.fix_state}`}>{item.fix_state === "fixed" ? "Available" : titleCase(item.fix_state)}</span></span>
    <span className="finding-source"><strong>{item.scanner}</strong><small>{titleCase(item.match_method)} · {Math.round(item.match_confidence * 100)}%</small></span>
    <span>{formatTime(item.last_seen_at)}</span><span><ChevronRight size={17} /></span>
  </button>;
}

function VulnerabilityDrawer({ vulnerabilityId, tab, onTab, onClose, onOpenAsset }: { vulnerabilityId: string; tab: VulnerabilityDetailTab; onTab: (tab: string) => void; onClose: () => void; onOpenAsset: (id: string) => void }) {
  const [detail, setDetail] = useState<VulnerabilityDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDetail(null); setError(null);
    api.vulnerability(vulnerabilityId).then(setDetail).catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load vulnerability"));
  }, [vulnerabilityId]);

  const winner = detail?.observations[0];
  return <div className="drawer-layer"><button className="drawer-scrim" onClick={onClose} aria-label="Close vulnerability detail" /><aside className="resource-drawer vulnerability-drawer" aria-label="Vulnerability detail">
    {!detail && !error ? <LoadingState compact /> : error ? <ErrorState message={error} subject="vulnerability" /> : detail && winner && <>
      <div className="drawer-header vulnerability-drawer-header"><button className="drawer-close" onClick={onClose}><X /></button><span className={`finding-icon large severity-${winner.severity}`}><Bug /></span><div><span>SOFTWARE VULNERABILITY</span><h2>{detail.vulnerability_id}</h2><p>{detail.component.display_name ?? detail.component.natural_key}</p></div><span className={`severity-badge ${winner.severity}`}>{titleCase(winner.severity)}</span></div>
      <div className="finding-summary-strip"><span className={`finding-state ${detail.state}`}>{titleCase(detail.state)}</span><span>CVSS <strong>{winner.cvss_score?.toFixed(1) ?? "Unknown"}</strong></span><span><strong>{detail.observations.filter((item) => !item.withdrawn_at).length}</strong> active sources</span><span>Last seen <strong>{formatTime(detail.last_seen_at)}</strong></span></div>
      <div className="drawer-tabs">{(["overview", "evidence", "sources"] as const).map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => onTab(item)}>{titleCase(item)}{item === "sources" && <small>{detail.observations.length}</small>}</button>)}</div>
      <div className="drawer-content">{tab === "overview" ? <VulnerabilityOverview detail={detail} winner={winner} onOpenAsset={onOpenAsset} /> : tab === "evidence" ? <VulnerabilityEvidence detail={detail} winner={winner} /> : <VulnerabilitySources detail={detail} />}</div>
    </>}
  </aside></div>;
}

function VulnerabilityOverview({ detail, winner, onOpenAsset }: { detail: VulnerabilityDetail; winner: VulnerabilityDetail["observations"][number]; onOpenAsset: (id: string) => void }) {
  const component = detail.component.attributes?.component as Record<string, unknown> | undefined;
  return <div className="detail-stack">
    <div className="vulnerability-narrative"><span>WHAT THE SCANNER MATCHED</span><p>{winner.description ?? "The scanner did not provide a vulnerability description."}</p></div>
    <DetailSection title="Affected component"><button className={`vulnerability-resource ${detail.component.asset_id ? "linked" : ""}`} disabled={!detail.component.asset_id} onClick={() => detail.component.asset_id && onOpenAsset(detail.component.asset_id)}><span className="asset-icon amber"><Package /></span><span><strong>{detail.component.display_name ?? "Uncorrelated software component"}</strong><small>{String(component?.purl ?? detail.component.natural_key)}</small></span><span className={`correlation-badge ${detail.component.asset_id ? "complete" : "unknown"}`}>{detail.component.asset_id ? "Inventory correlated" : "Reference only"}</span>{detail.component.asset_id && <ChevronRight />}</button><button className={`vulnerability-resource ${detail.target.asset_id ? "linked" : ""}`} disabled={!detail.target.asset_id} onClick={() => detail.target.asset_id && onOpenAsset(detail.target.asset_id)}><span className="asset-icon coral"><Activity /></span><span><strong>{detail.target.display_name ?? "Uncorrelated scan target"}</strong><small>{detail.target.natural_key}</small></span><span className={`correlation-badge ${detail.target.asset_id ? "complete" : "unknown"}`}>{detail.target.asset_id ? "Inventory correlated" : "Reference only"}</span>{detail.target.asset_id && <ChevronRight />}</button></DetailSection>
    <DetailSection title="Fix guidance"><div className={`fix-callout ${winner.fix_state}`}><ShieldCheck /><div><strong>{winner.fix_state === "fixed" ? "A fixed version is available" : `Fix state: ${titleCase(winner.fix_state)}`}</strong><p>{winner.fixed_versions.length ? `Upgrade to ${winner.fixed_versions.join(", ")}. Denali reports scanner guidance; it has not applied this change.` : "The scanner did not provide a fixed version."}</p></div></div></DetailSection>
    <DetailSection title="Vulnerability properties"><div className="property-grid"><Property label="Vulnerability ID" value={detail.vulnerability_id} mono /><Property label="Severity" value={titleCase(winner.severity)} /><Property label="CVSS score" value={winner.cvss_score?.toFixed(1) ?? "Unknown"} /><Property label="Exploit evidence" value={titleCase(winner.exploit_state)} /><Property label="Match method" value={titleCase(winner.match_method)} /><Property label="Match confidence" value={`${Math.round(winner.match_confidence * 100)}% (Denali derived)`} /><Property label="Scanner" value={winner.connector_id} /><Property label="Database schema" value={winner.database_version ?? "Unknown"} /></div></DetailSection>
    {winner.aliases.length > 0 && <DetailSection title="Aliases"><div className="alias-list">{winner.aliases.map((alias) => <code key={alias}>{alias}</code>)}</div></DetailSection>}
  </div>;
}

function VulnerabilityEvidence({ detail, winner }: { detail: VulnerabilityDetail; winner: VulnerabilityDetail["observations"][number] }) {
  return <div className="detail-stack"><div className="evidence-principle"><ShieldCheck /><div><strong>Scanner evidence with explicit limits</strong><p>Denali preserves the exact report locator and bounded match facts. Match confidence is derived from scanner match type; exploit status is never inferred from advisory links.</p></div></div><DetailSection title="Winning observation"><div className="evidence-card"><Property label="Source type" value={winner.evidence.source_type} /><Property label="Observed at" value={formatTime(winner.evidence.observed_at)} /><Property label="Evidence locator" value={winner.evidence.locator} mono /><Property label="Source UID" value={winner.source_uid} mono /><Property label="Match method" value={titleCase(winner.match_method)} /><Property label="Confidence" value={`${Math.round(winner.match_confidence * 100)}%`} />{winner.cvss_vector && <Property label="CVSS vector" value={winner.cvss_vector} mono />}<details><summary>Normalized evidence payload</summary><pre>{JSON.stringify(winner.evidence.payload, null, 2)}</pre></details></div></DetailSection><DetailSection title="Scanner metadata"><div className="evidence-card"><Property label="Connector" value={winner.connector_id} /><Property label="Connection" value={winner.connection_id} /><Property label="Scope" value={winner.scope_key} mono /><Property label="Database built" value={winner.database_built_at ? formatTime(winner.database_built_at) : "Unknown"} /><details><summary>Bounded source attributes</summary><pre>{JSON.stringify(winner.attributes, null, 2)}</pre></details></div></DetailSection></div>;
}

function VulnerabilitySources({ detail }: { detail: VulnerabilityDetail }) {
  return <div className="detail-stack"><div className="history-intro"><Waypoints /><div><strong>Independent scanner observations</strong><p>One canonical vulnerability can retain multiple sources. A source resolves only its own observation.</p></div></div><div className="vulnerability-sources">{detail.observations.map((item) => <div key={`${item.connector_id}-${item.connection_id}-${item.source_uid}`} className={item.withdrawn_at ? "withdrawn" : "active"}><span className={`history-dot ${item.state}`} /><div><strong>{item.connector_id}</strong><small>{item.connection_id} · {titleCase(item.match_method)} · {Math.round(item.match_confidence * 100)}%</small><p>{item.withdrawn_at ? `Withdrawn ${formatTime(item.withdrawn_at)}` : `Observed ${formatTime(item.source_observed_at)}`} · database {item.database_version ?? "unknown"}</p></div><span className={`finding-state ${item.withdrawn_at ? "resolved" : item.state}`}>{item.withdrawn_at ? "Withdrawn" : titleCase(item.state)}</span></div>)}</div></div>;
}

function isTemporalIssue(issue: Issue) {
  return issue.attributes.correlation === "deterministic_temporal" || issue.detection_count > 0;
}

function aggregateIssueEvaluations(evaluations: IssueEvaluation[]) {
  if (evaluations.length === 0) return null;
  const states = evaluations.map((item) => item.state);
  const state: IssueEvaluation["state"] = states.every((item) => item === "complete")
    ? "complete"
    : states.every((item) => item === "not_supported")
      ? "not_supported"
      : states.some((item) => item === "failed" || item === "partial")
        ? "partial"
        : "unknown";
  const latest = [...evaluations].sort((left, right) => right.evaluated_at.localeCompare(left.evaluated_at))[0];
  return {
    state,
    evaluated_at: latest.evaluated_at,
    detail: evaluations.map((item) => item.detail).filter(Boolean).join(" ") || null,
  };
}

function Issues({
  summary,
  issues,
  evaluations,
  navigation,
  onOpenIssue,
}: {
  summary: IssueSummary;
  issues: Issue[];
  evaluations: IssueEvaluation[];
  navigation: FilterNavigation;
  onOpenIssue: (id: string) => void;
}) {
  const search = navigation.values.q ?? "";
  const severity = navigation.values.severity ?? "all";
  const state = navigation.values.state ?? "open";
  const filtered = useMemo(() => issues.filter((issue) => {
    const haystack = `${issue.title} ${issue.rule_uid} ${issue.description}`.toLowerCase();
    return haystack.includes(search.toLowerCase()) &&
      (severity === "all" || issue.severity === severity) &&
      (state === "all" || issue.state === state);
  }), [issues, search, severity, state]);
  const evaluation = aggregateIssueEvaluations(evaluations);
  const confirmed = evaluations.reduce((total, item) => total + item.confirmed_issues, 0);
  const incomplete = evaluations.reduce((total, item) => total + item.incomplete_candidates, 0);

  return <div className="page-stack issues-page">
    <section className="page-intro"><div><span className="eyebrow">CONFIRMED CONSEQUENCES</span><h2>Prioritize what can actually happen.</h2><p>Denali combines independently observed inventory, findings, relationships, detections, and activity only when exact identifiers and explicit evidence support the conclusion.</p></div><div className="result-count"><strong>{summary.by_state.open ?? 0}</strong><span>open issues</span></div></section>
    <section className="issue-metric-grid">
      <FindingMetric severity="critical" count={summary.open_by_severity.critical ?? 0} />
      <FindingMetric severity="high" count={summary.open_by_severity.high ?? 0} />
      <div className="issue-signal-card"><span className="issue-signal-icon confirmed"><Gauge /></span><div><span>Confirmed issues</span><strong>{confirmed}</strong><small>Paths and temporal correlations</small></div></div>
      <div className="issue-signal-card"><span className={`issue-signal-icon ${incomplete ? "attention" : "complete"}`}>{incomplete ? <CircleHelp /> : <ShieldCheck />}</span><div><span>Correlation coverage</span><strong>{evaluation ? titleCase(evaluation.state) : "Not run"}</strong><small>{incomplete ? `${incomplete} incomplete candidates` : "No hidden path gaps"}</small></div></div>
    </section>
    <section className={`issue-coverage-banner ${evaluation?.state ?? "unknown"}`}>
      {evaluation?.state === "complete" ? <CircleCheck /> : <CircleHelp />}
      <div><strong>{evaluation?.state === "complete" ? "Correlation evaluation is complete" : "Correlation evaluation has unknowns"}</strong><span>{evaluation?.detail ?? "Every displayed issue is evidence-bearing. Graph paths require active edges; temporal issues require exact identity and sequence."}</span></div>
      {evaluation && <small>{formatTime(evaluation.evaluated_at)}</small>}
    </section>
    <section className="panel issues-panel">
      <div className="filterbar">
        <label className="search-field"><Search size={18} /><input value={search} onChange={(event) => navigation.set("q", event.target.value, "", "replace")} placeholder="Search issue, rule, or consequence…" /></label>
        <label className="select-field"><CircleAlert size={16} /><select value={severity} onChange={(event) => navigation.set("severity", event.target.value, "all")}><option value="all">All severities</option>{SEVERITY_ORDER.map((item) => <option key={item} value={item}>{titleCase(item)}</option>)}</select></label>
        <label className="select-field"><ListFilter size={16} /><select value={state} onChange={(event) => navigation.set("state", event.target.value, "open")}><option value="all">All states</option><option value="open">Open</option><option value="unknown">Unknown</option><option value="resolved">Resolved</option></select></label>
        {(search || severity !== "all" || state !== "open") && <button className="clear-button" onClick={() => navigation.clear(["q", "severity", "state"])}>Reset</button>}
      </div>
      <div className="issues-table" role="table" aria-label="AI issues and attack paths">
        <div className="issues-table-head" role="row"><span>Issue</span><span>Severity</span><span>State</span><span>Context</span><span>Evidence</span><span>Last confirmed</span><span /></div>
        {filtered.map((issue) => <IssueTableRow key={issue.id} issue={issue} onClick={() => onOpenIssue(issue.id)} />)}
        {filtered.length === 0 && <div className="empty-state"><ShieldCheck /><strong>{issues.length === 0 ? "No confirmed issues" : "No issues match these filters"}</strong><span>{issues.length === 0 ? "Run the deterministic issue evaluator after collecting inventory and findings." : "Reset the filters or include resolved issues."}</span></div>}
      </div>
    </section>
    <p className="fixture-note"><ShieldCheck size={15} /> Findings, detections, and activity never create graph edges. Graph issues require active capability assertions; temporal issues require exact identity and a strict event sequence.</p>
  </div>;
}

function IssueTableRow({ issue, onClick }: { issue: Issue; onClick: () => void }) {
  const temporal = isTemporalIssue(issue);
  return <button className="issues-table-row" role="row" onClick={onClick}>
    <span className="issue-title-cell"><span className={`finding-icon severity-${issue.severity}`}>{temporal ? <Gauge size={18} /> : <Network size={18} />}</span><span><strong>{issue.title}</strong><small>{issue.rule_uid} · {temporal ? "Temporal cross-signal correlation" : "Deterministic graph correlation"}</small></span></span>
    <span><span className={`severity-badge ${issue.severity}`}>{titleCase(issue.severity)}</span></span>
    <span><span className={`issue-state ${issue.state}`}>{titleCase(issue.state)}</span></span>
    <span>{issue.asset_count} {temporal ? "exact app" : "assets"}</span>
    <span>{temporal ? `${issue.detection_count + issue.activity_count} signals` : `${issue.finding_count} findings`}</span>
    <span>{formatTime(issue.last_seen_at)}</span><span><ChevronRight size={17} /></span>
  </button>;
}

function IssueDrawer({ issueId, tab, onTab, onClose }: { issueId: string; tab: IssueDetailTab; onTab: (tab: string) => void; onClose: () => void }) {
  const [detail, setDetail] = useState<IssueDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDetail(null); setError(null);
    api.issue(issueId).then(setDetail).catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load issue"));
  }, [issueId]);

  useEffect(() => {
    if (detail && tab === "path" && detail.path_edges.length === 0) onTab("overview");
  }, [detail, onTab, tab]);

  return <div className="drawer-layer"><button className="drawer-scrim" onClick={onClose} aria-label="Close issue detail" /><aside className="resource-drawer issue-drawer" aria-label="Issue detail">
    {!detail && !error ? <LoadingState compact /> : error ? <ErrorState message={error} subject="issue" /> : detail && (() => {
      const temporal = isTemporalIssue(detail);
      const tabs: IssueDetailTab[] = detail.path_edges.length > 0 ? ["overview", "path", "evidence"] : ["overview", "evidence"];
      const evidenceCount = detail.findings.length + detail.path_edges.length + detail.detections.length + detail.activities.length;
      return <>
      <div className="drawer-header issue-drawer-header"><button className="drawer-close" onClick={onClose}><X /></button><span className={`finding-icon large severity-${detail.severity}`}>{temporal ? <Gauge /> : <Network />}</span><div><span>{temporal ? "CROSS-SIGNAL SECURITY ISSUE" : "CONFIRMED SECURITY ISSUE"}</span><h2>{detail.title}</h2><p>{detail.rule_uid}</p></div><span className={`severity-badge ${detail.severity}`}>{titleCase(detail.severity)}</span></div>
      <div className="finding-summary-strip"><span className={`issue-state ${detail.state}`}>{titleCase(detail.state)}</span><span><strong>{Math.round(detail.confidence * 100)}%</strong> evidence confidence</span>{temporal ? <><span><strong>{detail.detections.length}</strong> detection</span><span><strong>{detail.activities.length}</strong> later activities</span></> : <><span><strong>{detail.findings.length}</strong> findings</span><span><strong>{detail.path_edges.length}</strong> confirmed edges</span></>}</div>
      <div className="drawer-tabs">{tabs.map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => onTab(item)}>{titleCase(item)}{item === "path" && <small>{detail.path_nodes.length}</small>}{item === "evidence" && <small>{evidenceCount}</small>}</button>)}</div>
      <div className="drawer-content">
        {tab === "overview" ? <IssueOverview detail={detail} /> : tab === "path" ? <IssuePath detail={detail} /> : <IssueEvidence detail={detail} />}
      </div>
    </>;
    })()}
  </aside></div>;
}

function IssueOverview({ detail }: { detail: IssueDetail }) {
  const temporal = isTemporalIssue(detail);
  const scopes = Array.isArray(detail.attributes.high_impact_scopes) ? detail.attributes.high_impact_scopes.map(String) : [];
  return <div className="detail-stack">
    <div className="issue-narrative"><span>WHY THIS IS AN ISSUE</span><p>{detail.description}</p></div>
    {temporal && <DetailSection title="Observed sequence"><div className="issue-chronology">
      {detail.detections.map((detection) => <div className="issue-chronology-step" key={detection.id}><span className="issue-chronology-icon"><Gauge /></span><div><small>1 · HIGH-IMPACT CONSENT</small><strong>{detection.title}</strong><p>{formatTime(detection.last_seen_at)}{scopes.length ? ` · ${scopes.join(", ")}` : ""}</p></div></div>)}
      {detail.activities.map((activity) => <div className="issue-chronology-step" key={activity.id}><span className="issue-chronology-icon"><Clock3 /></span><div><small>2 · SUBSEQUENT SUCCESSFUL SIGN-IN</small><strong>{activity.title}</strong><p>{formatTime(activity.occurred_at)}{activity.actors.length ? ` · ${activity.actors.map((actor) => actor.display_name ?? actor.external_uid).join(", ")}` : ""}</p></div></div>)}
      <div className="issue-chronology-limit"><CircleHelp /><span>This proves an exact-app consent event followed by later successful use. It does not prove those permissions were exercised or that the actor had malicious intent.</span></div>
    </div></DetailSection>}
    <DetailSection title="Risk and impact"><p className="finding-copy">{detail.risk}</p></DetailSection>
    <DetailSection title="Recommended remediation"><p className="finding-copy">{detail.remediation}</p></DetailSection>
    <DetailSection title="Correlation properties"><div className="property-grid"><Property label="Rule" value={detail.rule_uid} mono /><Property label={temporal ? "Correlation status" : "Path status"} value={titleCase(String(detail.attributes.path_status ?? "unknown"))} /><Property label="Confidence" value={`${Math.round(detail.confidence * 100)}%`} /><Property label="State" value={titleCase(detail.state)} /><Property label="First confirmed" value={formatTime(detail.first_seen_at)} /><Property label="Last evaluated" value={formatTime(detail.last_evaluated_at)} /></div></DetailSection>
    {detail.findings.length > 0 && <DetailSection title="Contributing findings"><div className="issue-finding-list">{detail.findings.map((finding) => <div key={finding.id}><span className={`finding-icon severity-${finding.severity}`}><CircleAlert /></span><span><strong>{finding.title}</strong><small>{titleCase(finding.role)} · {finding.rule_uid}</small></span><span className={`severity-badge ${finding.severity}`}>{titleCase(finding.severity)}</span></div>)}</div></DetailSection>}
  </div>;
}

function IssuePath({ detail }: { detail: IssueDetail }) {
  const byRole = Object.fromEntries(detail.path_nodes.map((node) => [node.role, node]));
  return <div className="detail-stack">
    <div className="evidence-principle"><Network /><div><strong>Confirmed capability path</strong><p>Every line below is an active relationship assertion. A finding reference cannot appear as an edge.</p></div></div>
    <div className="issue-path-graph">
      <IssueGraphNode node={byRole.agent} />
      <div className="issue-path-branches">
        <div><span className="graph-edge-label">RUNS AS</span><IssueGraphNode node={byRole.execution_identity} /></div>
        <div><span className="graph-edge-label">CAN INVOKE</span><IssueGraphNode node={byRole.write_tool} /><span className="graph-edge-label inline">CAN WRITE</span><IssueGraphNode node={byRole.sensitive_data} /></div>
      </div>
    </div>
    <DetailSection title="Edge assertions"><div className="issue-edge-list">{detail.path_edges.map((edge) => <div key={edge.id}><span><Network /></span><div><strong>{titleCase(edge.kind)}</strong><small>{titleCase(edge.assertion_type)} · {Math.round(edge.confidence * 100)}% confidence</small></div><em>{titleCase(edge.category)}</em></div>)}</div></DetailSection>
  </div>;
}

function IssueGraphNode({ node }: { node?: IssueDetail["path_nodes"][number] }) {
  if (!node) return null;
  const itemMeta = meta(node.kind); const Icon = itemMeta.icon;
  return <div className="issue-graph-node"><span className={`asset-icon ${itemMeta.color}`}><Icon /></span><span><small>{titleCase(node.role)}</small><strong>{node.display_name ?? shortKey(node.natural_key)}</strong><code>{node.natural_key}</code></span></div>;
}

function IssueEvidence({ detail }: { detail: IssueDetail }) {
  const evidenceCount = detail.findings.length + detail.path_edges.length + detail.detections.length + detail.activities.length;
  return <div className="detail-stack">
    <div className="evidence-principle"><ShieldCheck /><div><strong>{evidenceCount} independent evidence links</strong><p>The issue stores references to source findings, relationship assertions, runtime detections, and activity observations; it does not copy or invent their evidence.</p></div></div>
    {detail.findings.length > 0 && <DetailSection title="Finding evidence"><div className="issue-evidence-list">{detail.findings.map((finding) => <div key={finding.id}><span>{titleCase(finding.role)}</span><strong>{finding.title}</strong><code>{finding.evidence.locator}</code></div>)}</div></DetailSection>}
    {detail.path_edges.length > 0 && <DetailSection title="Relationship evidence"><div className="issue-evidence-list">{detail.path_edges.map((edge) => <div key={edge.id}><span>{titleCase(edge.kind)}</span><strong>{titleCase(edge.assertion_type)} · {Math.round(edge.confidence * 100)}% confidence</strong><code>{edge.evidence.locator}</code></div>)}</div></DetailSection>}
    {detail.detections.length > 0 && <DetailSection title="Detection evidence"><div className="issue-evidence-list">{detail.detections.map((detection) => <div key={detection.id}><span>{titleCase(detection.role)}</span><strong>{detection.title}</strong><code>{detection.rule_uid} · last seen {formatTime(detection.last_seen_at)}</code></div>)}</div></DetailSection>}
    {detail.activities.length > 0 && <DetailSection title="Activity evidence"><div className="issue-evidence-list">{detail.activities.map((activity) => <div key={activity.id}><span>{titleCase(activity.role)}</span><strong>{activity.title} · {formatTime(activity.occurred_at)}</strong><code>{activity.evidence.locator}{activity.actors.length ? ` · ${activity.actors.map((actor) => actor.display_name ?? actor.external_uid).join(", ")}` : ""}</code></div>)}</div></DetailSection>}
  </div>;
}

function CodeToCloud({
  deployments,
  observations,
  onOpenAsset,
  onOpenFinding,
  onOpenVulnerability,
}: {
  deployments: CodeToCloudDeployment[];
  observations: CodeToCloudObservation[];
  onOpenAsset: (id: string) => void;
  onOpenFinding: (id: string) => void;
  onOpenVulnerability: (id: string) => void;
}) {
  const repositoryCount = new Set(deployments.map((item) => item.repository_id)).size;
  const modelCount = new Set(
    deployments.flatMap((item) => item.models.map((model) => model.id)),
  ).size;
  const correlationTotals = observations.reduce(
    (total, observation) => ({
      declarations: total.declarations + (observation.correlation_summary?.declarations ?? 0),
      proven: total.proven + (observation.correlation_summary?.proven ?? 0),
      ambiguous: total.ambiguous + (observation.correlation_summary?.ambiguous ?? 0),
      unmatched: total.unmatched + (observation.correlation_summary?.unmatched ?? 0),
    }),
    { declarations: 0, proven: 0, ambiguous: 0, unmatched: 0 },
  );

  return <div className="page-stack code-to-cloud-page">
    <section className="page-intro">
      <div><span className="eyebrow">EVIDENCE-LED LINEAGE</span><h2>Trace AI from source to runtime.</h2><p>Denali joins source-controlled deployment declarations to independently observed cloud workloads using exact, reviewable identifiers.</p></div>
      <div className="result-count"><strong>{deployments.length}</strong><span>proven deployments</span></div>
    </section>

    <section className="lineage-metric-grid">
      <div className="lineage-metric"><span className="lineage-metric-icon repository"><Code2 /></span><div><small>Repositories</small><strong>{repositoryCount}</strong><em>Source-controlled systems</em></div></div>
      <div className="lineage-metric"><span className="lineage-metric-icon workload"><Activity /></span><div><small>Deployed workloads</small><strong>{deployments.length}</strong><em>Observed in cloud control planes</em></div></div>
      <div className="lineage-metric"><span className="lineage-metric-icon model"><BrainCircuit /></span><div><small>Related models</small><strong>{modelCount}</strong><em>Observed runtime + declared source</em></div></div>
      <div className="lineage-metric"><span className="lineage-metric-icon identity"><Fingerprint /></span><div><small>Execution identities</small><strong>{deployments.filter((item) => item.identity).length}</strong><em>Independently observed roles</em></div></div>
    </section>

    <section className="lineage-trust-banner">
      <ShieldCheck />
      <div><strong>{deployments.length} deterministic deployment links</strong><p>Each link requires literal source identifiers to match independently observed, provider-scoped runtime identifiers. Shared model names can corroborate a link, but never create one.</p></div>
      <span>100% correlation confidence</span>
    </section>

    <section className="panel correlation-observability">
      <div className="correlation-observability-head"><div><span className="eyebrow">CORRELATION COVERAGE</span><h3>Every candidate has a disposition.</h3><p>Source collection and analysis health stay separate from proven deployment links.</p></div><div><strong>{correlationTotals.declarations}</strong><span>declarations evaluated</span></div></div>
      <div className="correlation-status-grid"><div className="proven"><small>Proven</small><strong>{correlationTotals.proven}</strong><span>Exact code + control-plane join</span></div><div className="ambiguous"><small>Ambiguous</small><strong>{correlationTotals.ambiguous}</strong><span>No relationship emitted</span></div><div><small>Unmatched</small><strong>{correlationTotals.unmatched}</strong><span>No eligible observed workload</span></div><div><small>Repositories</small><strong>{observations.length}</strong><span>{observations.filter((item) => item.source_state === "failed" || item.analysis_state === "failed").length} failed collections</span></div></div>
      {observations.length > 0 ? <div className="correlation-observation-list">{observations.map((observation) => <details key={`${observation.connection_id}:${observation.repository_natural_key}`} open={observation.source_state === "failed" || observation.analysis_state === "partial" || observation.analysis_state === "failed"}><summary><span className={`correlation-observation-state ${observation.source_state === "failed" || observation.analysis_state === "failed" ? "failed" : observation.analysis_state === "partial" ? "partial" : "complete"}`}>{observation.source_state === "failed" || observation.analysis_state === "failed" ? <CircleAlert /> : observation.analysis_state === "partial" ? <CircleHelp /> : <CircleCheck />}</span><span><strong>{observation.repository_name ?? observation.repository_natural_key}</strong><small>{observation.evidence?.payload.commit ? `Revision ${String(observation.evidence.payload.commit).slice(0, 12)}` : "Revision unavailable"}</small></span><span className="correlation-observation-counts"><b>{observation.correlation_summary?.proven ?? 0} proven</b><small>{observation.correlation_summary?.ambiguous ?? 0} ambiguous · {observation.correlation_summary?.unmatched ?? 0} unmatched</small></span></summary><div className="correlation-candidates">{observation.source_detail && <p><CircleAlert /> Source: {titleCase(observation.source_detail)}</p>}{observation.analysis_detail && <p><CircleHelp /> Analysis: {observation.analysis_detail}</p>}{observation.correlation_candidates.map((candidate, index) => <div key={`${candidate.source_path}:${candidate.source_line}:${index}`} className={candidate.status}><span>{candidate.status === "proven" ? <CircleCheck /> : candidate.status === "ambiguous" ? <CircleHelp /> : <CircleAlert />}</span><div><strong>{candidate.deployment_identifier}</strong><small>{titleCase(candidate.service)} · {candidate.source_path}:{candidate.source_line}</small><code>{candidate.matched_workloads.length > 0 ? candidate.matched_workloads.join(" · ") : "No exact observed workload match"}</code></div><b>{titleCase(candidate.status)}</b></div>)}</div></details>)}</div> : <div className="correlation-observability-empty"><CircleHelp /><span><strong>No repository analysis recorded</strong><small>Use Collect source & correlate on a configured GitHub connection.</small></span></div>}
    </section>

    {deployments.length === 0 ? <section className="panel empty-state"><CloudCog /><strong>No proven deployments yet</strong><span>Collect a repository and an independently observed cloud workload, then run the code-to-cloud correlator.</span></section> : <section className="deployment-list">
      {deployments.map((deployment) => <DeploymentCard key={deployment.id} deployment={deployment} onOpenAsset={onOpenAsset} onOpenFinding={onOpenFinding} onOpenVulnerability={onOpenVulnerability} />)}
    </section>}

    <p className="fixture-note"><ShieldCheck size={15} /> Code-to-cloud edges are lineage assertions, not security issues. Denali creates an issue only after separate evidence proves a harmful consequence.</p>
  </div>;
}

function DeploymentCard({
  deployment,
  onOpenAsset,
  onOpenFinding,
  onOpenVulnerability,
}: {
  deployment: CodeToCloudDeployment;
  onOpenAsset: (id: string) => void;
  onOpenFinding: (id: string) => void;
  onOpenVulnerability: (id: string) => void;
}) {
  const sourcePath = stringValue(deployment.attributes.source_path) ?? stringValue(deployment.evidence.payload.source_path);
  const sourceLine = stringValue(deployment.attributes.source_line) ?? stringValue(deployment.evidence.payload.source_line);
  const entry = stringValue(deployment.attributes.entry) ?? stringValue(deployment.evidence.payload.entry);
  const service = stringValue(deployment.workload_attributes.service) ?? "cloud workload";
  const logicalId = stringValue(deployment.workload_attributes.logical_id) ?? stringValue(deployment.evidence.payload.observed_logical_id);
  const location = stringValue(deployment.workload_attributes.region)
    ?? stringValue(deployment.workload_attributes.location);
  const cloudScope = stringValue(deployment.workload_attributes.account_id)
    ?? stringValue(deployment.workload_attributes.subscription_id)
    ?? stringValue(deployment.workload_attributes.project)
    ?? stringValue(deployment.workload_attributes.project_id)
    ?? stringValue(deployment.workload_attributes.project_number);
  const artifactIdentityStatus = stringValue(deployment.attributes.artifact_identity_status) ?? "not_evaluated";
  const deploymentAssetId = stringValue(deployment.attributes.deployment_asset_id);
  const manifestPath = stringValue(deployment.attributes.cdk_manifest_path);
  const repositoryRevision = stringValue(deployment.attributes.repository_revision) ?? stringValue(deployment.evidence.payload.repository_revision);
  const artifactFindings = deployment.code_findings.filter((finding) => finding.applicability === "artifact_included");
  const repositoryOnlyFindings = deployment.code_findings.filter((finding) => finding.applicability !== "artifact_included");
  const vulnerabilityCoverage = deployment.vulnerability_coverage;
  const vulnerabilityArtifactStatus = vulnerabilityCoverage?.artifact_identity_status ?? "not_evaluated";
  const vulnerabilityCount = deployment.artifact_vulnerability_count;
  const vulnerabilityIdCount = deployment.artifact_vulnerability_id_count;
  const visibleVulnerabilityCount = deployment.artifact_vulnerabilities.length;

  return <article className="panel deployment-card">
    <header className="deployment-card-head">
      <div><span className="eyebrow">CORRELATED DEPLOYMENT</span><h3>{deployment.workload_name}</h3><p>{deployment.repository_name} → {titleCase(service)}</p></div>
      <span className="deterministic-badge"><Check /> Identifiers matched</span>
    </header>

    <div className="lineage-flow" aria-label={`Deployment path from ${deployment.repository_name} to ${deployment.workload_name}`}>
      {deployment.agent
        ? <LineageNode icon={Bot} color="coral" label="Agent from code" title={deployment.agent.display_name} detail={`${deployment.repository_name} · ${sourcePath ? `${sourcePath}${sourceLine ? `:${sourceLine}` : ""}` : "source observed"}`} onClick={() => onOpenAsset(deployment.agent!.id)} />
        : <LineageNode icon={Code2} color="slate" label="Source repository" title={deployment.repository_name} detail={sourcePath ? `${sourcePath}${sourceLine ? `:${sourceLine}` : ""}` : deployment.repository_natural_key} onClick={() => onOpenAsset(deployment.repository_id)} />}
      <span className="lineage-arrow"><span>DEPLOYS</span><ChevronRight /></span>
      <LineageNode icon={Activity} color="coral" label={titleCase(service)} title={deployment.workload_name} detail={logicalId ?? deployment.workload_natural_key} onClick={() => onOpenAsset(deployment.workload_id)} />
      <span className="lineage-arrow"><span>RUNS AS</span><ChevronRight /></span>
      {deployment.identity ? <LineageNode icon={Fingerprint} color="violet" label="Execution identity" title={deployment.identity.display_name} detail={`${titleCase(deployment.identity.assertion_type)} · ${Math.round(deployment.identity.confidence * 100)}%`} onClick={() => onOpenAsset(deployment.identity!.id)} /> : <div className="lineage-node unknown"><span className="asset-icon slate"><CircleHelp /></span><span><small>Execution identity</small><strong>Not observed</strong><code>Coverage remains explicit</code></span></div>}
      <span className="lineage-arrow"><span>CALLS</span><ChevronRight /></span>
      <div className="lineage-node-group">
        {deployment.models.length > 0
          ? deployment.models.map((model) => <LineageNode key={model.id} icon={BrainCircuit} color="violet" label={model.relationship_source === "workload" ? "Runtime model" : "Model from code"} title={model.display_name} detail={`${titleCase(model.assertion_type)} · ${Math.round(model.confidence * 100)}%`} onClick={() => onOpenAsset(model.id)} compact />)
          : <div className="lineage-node unknown"><span className="asset-icon slate"><CircleHelp /></span><span><small>Runtime model</small><strong>Not observed</strong><code>No exact workload model edge</code></span></div>}
      </div>
    </div>

    <div className="deployment-evidence-grid">
      <div><span>Source declaration</span><strong>{sourcePath ?? "Unknown source path"}{sourceLine ? `:${sourceLine}` : ""}</strong><small>{entry ? `Entry ${entry}` : "Literal deployment declaration"}</small></div>
      <div><span>Observed runtime</span><strong>{[cloudScope, location].filter(Boolean).join(" · ") || "Cloud control plane"}</strong><small>{logicalId ?? deployment.workload_natural_key}</small></div>
      <div><span>Evidence class</span><strong>{titleCase(deployment.assertion_type)} · {Math.round(deployment.confidence * 100)}%</strong><small>Independent code and control-plane observations</small></div>
    </div>

    {(deployment.tools ?? []).length > 0 ? <div className="declared-action-surface">
      <div className="declared-action-head"><Zap /><div><strong>Declared tool and action surface</strong><span>Static source call sites show what the agent is coded to invoke. These declarations are not presented as proof that an action executed.</span></div><b>NOT OBSERVED</b></div>
      <div className="declared-action-grid">
        {deployment.tools.map((tool) => <div className="declared-action" key={tool.id}>
          <button onClick={() => onOpenAsset(tool.id)}><span className="asset-icon amber"><Zap /></span><span><small>{tool.provider ? titleCase(tool.provider) : "Declared tool"}</small><strong>{tool.display_name}</strong><code>{tool.operation ?? tool.natural_key}</code></span><ChevronRight /></button>
          {tool.actions.map((action) => <button className="declared-action-target" key={action.relationship_id} onClick={() => onOpenAsset(action.target_id)}><span>{titleCase(action.kind)}</span><strong>{action.target_name}</strong><small>{action.operation ?? titleCase(action.target_kind)} · declared</small></button>)}
        </div>)}
      </div>
    </div> : null}

    <div className="deployment-provenance">
      {artifactIdentityStatus === "matched" ? <div className="provenance-callout matched"><PackageCheck /><div><strong>Deployment artifact identity matched</strong><span>The live CDK asset locator exactly matches asset <code>{deploymentAssetId ?? "recorded in the manifest"}</code>{manifestPath ? <> in <code>{manifestPath}</code></> : null}. This compares artifact identity—not runtime execution.</span></div></div> : <div className="provenance-callout unknown"><CircleHelp /><div><strong>Deployment artifact identity {artifactIdentityStatus === "not_matched" ? "not matched locally" : "not evaluated"}</strong><span>{artifactIdentityStatus === "not_matched" ? "No exact live locator was found in the inspected local CDK manifests. This is not proof of deployment drift." : "Denali lacks either an exact live deployment locator or a local CDK asset manifest for comparison."}</span></div></div>}
      <div className="provenance-callout unattested"><GitBranch /><div><strong>Source revision unattested</strong><span>The deployed artifact contains no independently verifiable Git revision. Checkout <code>{repositoryRevision ?? "unknown"}</code> is analysis context, not proof of what is running.</span></div></div>
    </div>

    <div className={`artifact-vulnerabilities ${vulnerabilityArtifactStatus}`}>
      <div className="artifact-vulnerabilities-head">
        {vulnerabilityArtifactStatus === "matched" ? <PackageCheck /> : <CircleHelp />}
        <div>
          <strong>{vulnerabilityArtifactStatus === "matched"
            ? vulnerabilityCoverage?.state === "complete"
              ? vulnerabilityCount > 0
                ? `${vulnerabilityCount} vulnerable component occurrence${vulnerabilityCount === 1 ? "" : "s"} across ${vulnerabilityIdCount} vulnerabilit${vulnerabilityIdCount === 1 ? "y" : "ies"}`
                : "Artifact vulnerability scan complete · no vulnerable components reported"
              : `Artifact vulnerability scan ${vulnerabilityCoverage?.state ?? "unknown"}`
            : vulnerabilityArtifactStatus === "not_matched"
              ? "Latest vulnerability scan does not match this deployment artifact"
              : "Deployment artifact has not been vulnerability-scanned"}</strong>
          <span>{vulnerabilityArtifactStatus === "matched"
            ? `The scanner reported the exact deployed artifact ${vulnerabilityCoverage?.artifact_identity_method === "exact_digest" ? "digest" : "locator"}. Component presence does not prove runtime execution.${vulnerabilityCoverage?.state !== "complete" ? " Coverage is incomplete, so absence is not a safety claim." : ""}`
            : vulnerabilityArtifactStatus === "not_matched"
              ? "The scanner subject and live deployment identity differ. Denali will not assign those results to this workload."
              : "No scanner-reported artifact identity has been correlated with this live deployment."}</span>
          {vulnerabilityCoverage ? <code>{vulnerabilityCoverage.artifact_locator}</code> : null}
        </div>
      </div>
      {vulnerabilityArtifactStatus === "matched" && visibleVulnerabilityCount > 0 ? <div className="artifact-vulnerability-list">
        {deployment.artifact_vulnerabilities.map((vulnerability) => <button key={vulnerability.id} onClick={() => onOpenVulnerability(vulnerability.id)}>
          <span className={`finding-icon severity-${vulnerability.severity}`}><Bug /></span>
          <span><strong>{vulnerability.vulnerability_id}{vulnerability.component_name ? ` in ${vulnerability.component_name}` : ""}</strong><small>{vulnerability.component_purl ?? vulnerability.title ?? "Scanner-reported component match"}{vulnerability.fixed_versions.length > 0 ? ` · Fix ${vulnerability.fixed_versions.join(", ")}` : ""}</small></span>
          <span className={`severity-badge ${vulnerability.severity}`}>{titleCase(vulnerability.severity)}</span><ChevronRight />
        </button>)}
        {vulnerabilityCount > visibleVulnerabilityCount ? <p className="artifact-vulnerability-overflow">Showing the {visibleVulnerabilityCount} highest-severity component occurrences. Open AI vulnerabilities to review all {vulnerabilityCount}.</p> : null}
      </div> : null}
    </div>

    <div className="artifact-findings">
      <div className="artifact-findings-head"><FileCode2 /><div><strong>{artifactFindings.length} source configuration finding call site{artifactFindings.length === 1 ? "" : "s"} included in this artifact</strong><span>Denali traced literal local-module imports from the declared bundle entry. This proves code inclusion—not that runtime execution reached the call.</span></div></div>
      {artifactFindings.length > 0 ? <div className="repository-finding-list">{artifactFindings.map((finding) => <FindingApplicabilityRow key={finding.id} finding={finding} onOpenFinding={onOpenFinding} showChain />)}</div> : <p>No open repository finding was traced into this artifact.</p>}
    </div>

    {repositoryOnlyFindings.length > 0 ? <div className="repository-findings">
      <div className="repository-findings-head"><CircleHelp /><div><strong>Repository-only context</strong><span>These call sites exist in the repository but are not reachable from this artifact's declared entry. They are not assigned to this workload.</span></div></div>
      <div className="repository-finding-list">{repositoryOnlyFindings.map((finding) => <FindingApplicabilityRow key={finding.id} finding={finding} onOpenFinding={onOpenFinding} />)}</div>
    </div> : null}
  </article>;
}

function FindingApplicabilityRow({
  finding,
  onOpenFinding,
  showChain = false,
}: {
  finding: CodeToCloudDeployment["code_findings"][number];
  onOpenFinding: (id: string) => void;
  showChain?: boolean;
}) {
  const location = finding.source_path ? `${finding.source_path}${finding.source_line ? `:${finding.source_line}` : ""}` : "Unknown source location";
  const chain = showChain && finding.import_chain?.length ? finding.import_chain.join(" → ") : null;
  return <button onClick={() => onOpenFinding(finding.id)}><span className={`finding-icon severity-${finding.severity}`}><CircleAlert /></span><span><strong>{finding.title}</strong><small>{finding.rule_uid} · {location}</small>{chain ? <small className="import-chain">Bundle path: {chain}</small> : null}</span><span className={`severity-badge ${finding.severity}`}>{titleCase(finding.severity)}</span><ChevronRight /></button>;
}

function LineageNode({
  icon: Icon,
  color,
  label,
  title,
  detail,
  onClick,
  compact = false,
}: {
  icon: LucideIcon;
  color: string;
  label: string;
  title: string;
  detail: string;
  onClick: () => void;
  compact?: boolean;
}) {
  return <button className={`lineage-node ${compact ? "compact" : ""}`} onClick={onClick}><span className={`asset-icon ${color}`}><Icon /></span><span><small>{label}</small><strong>{title}</strong><code>{detail}</code></span><ChevronRight /></button>;
}

function stringValue(value: unknown): string | null {
  if (typeof value === "string" && value.length > 0) return value;
  if (typeof value === "number") return String(value);
  return null;
}

const ACTIVITY_META: Record<RuntimeActivity["category"], { label: string; icon: LucideIcon; color: string }> = {
  model_invocation: { label: "Model invocation", icon: BrainCircuit, color: "violet" },
  agent_invocation: { label: "Agent invocation", icon: Bot, color: "coral" },
  retrieval: { label: "Retrieval", icon: Database, color: "green" },
  tool_invocation: { label: "Tool invocation", icon: Zap, color: "amber" },
  ai_app_sign_in: { label: "AI app sign-in", icon: Fingerprint, color: "violet" },
  admin_change: { label: "Admin change", icon: CloudCog, color: "blue" },
  data_access: { label: "Data access", icon: Database, color: "green" },
  other: { label: "Other activity", icon: Activity, color: "slate" },
};

const ENTRA_PLANES = {
  applications: "entra_ai_application_inventory",
  delegated: "entra_oauth_delegated_grants",
  applicationPermissions: "entra_application_permissions",
  signIns: "entra_ai_signins",
  audits: "entra_ai_directory_audits",
} as const;

function ShadowAiPage({
  assets,
  activities,
  coverage,
  navigation,
  onOpenAsset,
  onOpenActivity,
}: {
  assets: Asset[];
  activities: RuntimeActivity[];
  coverage: Coverage[];
  navigation: FilterNavigation;
  onOpenAsset: (id: string) => void;
  onOpenActivity: (id: string) => void;
}) {
  const search = navigation.values.q ?? "";
  const category = navigation.values.category ?? "all";
  const governance = navigation.values.governance ?? "all";
  const connection = navigation.values.connection ?? "latest";
  const allApplications = useMemo(
    () => assets.filter((asset) => asset.kind === "ai_application"),
    [assets],
  );
  const allEntraActivity = useMemo(
    () => activities.filter(
      (item) => item.provider === "Microsoft Entra" &&
        (item.category === "ai_app_sign_in" || item.category === "admin_change"),
    ),
    [activities],
  );
  const applicationCoverage = useMemo(
    () => coverage
      .filter((item) => item.connector_id === "denali.entra_ai" && item.plane === ENTRA_PLANES.applications)
      .sort((left, right) => right.collected_at.localeCompare(left.collected_at)),
    [coverage],
  );
  const connections = useMemo(
    () => [...new Set([
      ...allApplications.map((asset) => asset.connection_id),
      ...allEntraActivity.map((item) => item.connection_id),
    ].filter((value): value is string => value !== null))].sort(),
    [allApplications, allEntraActivity],
  );
  const latestActiveConnection = useMemo(
    () => [...allEntraActivity]
      .sort((left, right) => right.occurred_at.localeCompare(left.occurred_at))[0]?.connection_id ??
      applicationCoverage[0]?.connection_id ??
      connections[0],
    [allEntraActivity, applicationCoverage, connections],
  );
  const selectedConnection = connection === "all"
    ? undefined
    : connection === "latest"
      ? latestActiveConnection
      : connection;
  const applications = useMemo(
    () => allApplications.filter((asset) => !selectedConnection || asset.connection_id === selectedConnection),
    [allApplications, selectedConnection],
  );
  const categories = useMemo(
    () => [...new Set(applications.map((asset) => stringValue(asset.attributes?.catalog_category)).filter((value): value is string => value !== null))].sort(),
    [applications],
  );
  const filtered = useMemo(() => applications.filter((asset) => {
    const attributes = asset.attributes ?? {};
    const haystack = `${asset.display_name ?? ""} ${asset.natural_key} ${stringValue(attributes.catalog_name) ?? ""} ${stringValue(attributes.publisher_name) ?? ""}`.toLowerCase();
    return haystack.includes(search.toLowerCase()) &&
      (category === "all" || attributes.catalog_category === category) &&
      (governance === "all" || asset.governance_status === governance);
  }), [applications, category, governance, search]);
  const entraActivity = useMemo(
    () => allEntraActivity.filter((item) => !selectedConnection || item.connection_id === selectedConnection),
    [allEntraActivity, selectedConnection],
  );
  const signIns = entraActivity.filter((item) => item.category === "ai_app_sign_in");
  const adminChanges = entraActivity.filter((item) => item.category === "admin_change");
  const delegatedGrants = applications.reduce((total, asset) => total + attributeNumber(asset, "delegated_grant_count"), 0);
  const appPermissions = applications.reduce((total, asset) => total + attributeNumber(asset, "application_permission_count"), 0);
  const latestCoverage = useMemo(() => {
    const result = new Map<string, Coverage>();
    coverage.filter((item) => item.connector_id === "denali.entra_ai" && (!selectedConnection || item.connection_id === selectedConnection)).forEach((item) => {
      const existing = result.get(item.plane);
      if (!existing || item.collected_at > existing.collected_at) result.set(item.plane, item);
    });
    return result;
  }, [coverage, selectedConnection]);
  const hasEntraBoundary = coverage.some(
    (item) => item.connector_id === "denali.entra_ai",
  );

  if (!hasEntraBoundary) {
    return <div className="page-stack shadow-ai-page">
      <section className="page-intro"><div><span className="eyebrow">ENTERPRISE AI APPLICATIONS</span><h2>AI application discovery is outside this Golden Path.</h2><p>This workspace currently contains two code-to-cloud applications in AWS and Google Cloud. It has no declared Microsoft Entra evidence boundary.</p></div><div className="result-count"><strong>N/A</strong><span>Entra application coverage</span></div></section>
      <section className="panel applicability-boundary"><CircleHelp /><div><span className="eyebrow">NOT APPLICABLE</span><h3>No Microsoft Entra tenant is connected</h3><p>Denali will not turn missing Entra collection into four reassuring zeroes. Connect an Entra tenant when workforce AI application discovery belongs in the demo; until then, this page is explicitly out of scope.</p></div></section>
      <section className="shadow-principle"><ShieldCheck /><div><strong>The rest of the Golden Path remains valid.</strong><span>Anna and Summit continue to demonstrate source, deployment, identity, model, component, posture, and runtime evidence without an unrelated SaaS application fixture.</span></div></section>
    </div>;
  }

  return <div className="page-stack shadow-ai-page">
    <section className="page-intro"><div><span className="eyebrow">ENTERPRISE AI APPLICATIONS</span><h2>See the AI your workforce has connected.</h2><p>Microsoft Entra applications, consent, permissions, and observed use—catalog matches for review, never risk verdicts by themselves.</p></div><div className="result-count"><strong>{applications.length}</strong><span>catalog-matched AI applications</span><small>{categories.length} application categories</small></div></section>
    <section className="shadow-signal-grid">
      <ShadowSignal icon={AppWindow} label="AI applications" value={applications.length} detail="exact catalog matches" coverage={latestCoverage.get(ENTRA_PLANES.applications)} />
      <ShadowSignal icon={Link2} label="Delegated grants" value={delegatedGrants} detail="user-context permissions" coverage={latestCoverage.get(ENTRA_PLANES.delegated)} />
      <ShadowSignal icon={Fingerprint} label="Application permissions" value={appPermissions} detail="non-human access" coverage={latestCoverage.get(ENTRA_PLANES.applicationPermissions)} />
      <ShadowSignal icon={Activity} label="Observed sign-ins" value={signIns.length} detail={`${adminChanges.length} directory changes`} coverage={latestCoverage.get(ENTRA_PLANES.signIns)} />
    </section>
    <section className="shadow-principle"><CircleHelp /><div><strong>A catalog match means “review this application.”</strong><span>Denali does not claim an application is unsanctioned, unsafe, or training on company data without separate evidence and policy.</span></div></section>
    <section className="panel shadow-app-panel">
      <div className="filterbar">
        <label className="search-field"><Search size={18} /><input value={search} onChange={(event) => navigation.set("q", event.target.value, "", "replace")} placeholder="Search application or publisher…" /></label>
        <label className="select-field"><Waypoints size={16} /><select value={connection} onChange={(event) => navigation.set("connection", event.target.value, "latest")}><option value="latest">Most recently active tenant</option><option value="all">All connected tenants</option>{connections.map((item) => <option value={item} key={item}>{entraConnectionLabel(item)}</option>)}</select></label>
        <label className="select-field"><AppWindow size={16} /><select value={category} onChange={(event) => navigation.set("category", event.target.value, "all")}><option value="all">All categories</option>{categories.map((item) => <option value={item} key={item}>{titleCase(item)}</option>)}</select></label>
        <label className="select-field"><ShieldCheck size={16} /><select value={governance} onChange={(event) => navigation.set("governance", event.target.value, "all")}><option value="all">All governance</option><option value="approved">Approved</option><option value="unreviewed">Unreviewed</option><option value="unwanted">Unwanted</option></select></label>
        {(search || connection !== "latest" || category !== "all" || governance !== "all") && <button className="clear-button" onClick={() => navigation.clear(["q", "connection", "category", "governance"])}>Reset</button>}
      </div>
      <div className="shadow-app-table" role="table" aria-label="Enterprise AI applications">
        <div className="shadow-app-head" role="row"><span>Application</span><span>Category</span><span>Permissions</span><span>Publisher</span><span>Governance</span><span>Last seen</span><span /></div>
        {filtered.map((asset) => <ShadowApplicationRow key={asset.id} asset={asset} onClick={() => onOpenAsset(asset.id)} />)}
        {filtered.length === 0 && <div className="empty-state"><AppWindow /><strong>{applications.length === 0 ? "No AI applications have been collected" : "No applications match these filters"}</strong><span>{applications.length === 0 ? "Run the Microsoft Entra connector and inspect its coverage state." : "Reset the filters to see the full application inventory."}</span></div>}
      </div>
    </section>
    <section className="panel shadow-activity-panel">
      <PanelHeader eyebrow="OBSERVED USE" title="Recent Entra activity" />
      <div className="runtime-table" role="table" aria-label="Recent Entra AI activity">
        <div className="runtime-table-head" role="row"><span>Activity</span><span>Type</span><span>Outcome</span><span>Actor</span><span>Provider</span><span>Occurred</span><span /></div>
        {entraActivity.slice(0, 8).map((item) => <RuntimeActivityRow key={item.id} item={item} onClick={() => onOpenActivity(item.id)} />)}
        {entraActivity.length === 0 && <div className="empty-state"><Activity /><strong>No Entra AI activity is currently visible</strong><span>Check sign-in and directory-audit coverage before treating this as no use.</span></div>}
      </div>
    </section>
    <p className="fixture-note"><ShieldCheck size={15} /> Application discovery and runtime activity remain facts. Governance decisions and security findings are evaluated separately.</p>
  </div>;
}

function ShadowSignal({ icon: Icon, label, value, detail, coverage }: { icon: LucideIcon; label: string; value: number; detail: string; coverage?: Coverage }) {
  const state = coverage?.state ?? "unknown";
  return <div className={`shadow-signal ${state}`}><span><Icon /></span><div><small>{label}</small><strong>{value}</strong><em>{detail}</em></div><b>{titleCase(state)}</b></div>;
}

function ShadowApplicationRow({ asset, onClick }: { asset: Asset; onClick: () => void }) {
  const attributes = asset.attributes ?? {};
  const delegated = attributeNumber(asset, "delegated_grant_count");
  const application = attributeNumber(asset, "application_permission_count");
  const publisher = stringValue(attributes.verified_publisher) ?? stringValue(attributes.publisher_name) ?? "Not provided";
  return <button className="shadow-app-row" role="row" onClick={onClick}>
    <span className="resource-cell"><span className="asset-icon blue"><AppWindow /></span><span><strong>{asset.display_name ?? shortKey(asset.natural_key)}</strong><small>{stringValue(attributes.catalog_name) ?? "Catalog matched"} · {attributes.account_enabled === false ? "Disabled" : "Enabled"}</small></span></span>
    <span>{titleCase(stringValue(attributes.catalog_category) ?? "uncategorized")}</span>
    <span className="permission-summary"><strong>{delegated} delegated</strong><small>{application} application</small></span>
    <span className="publisher-cell">{publisher}</span>
    <span><span className={`governance-badge ${asset.governance_status}`}>{titleCase(asset.governance_status)}</span></span>
    <span>{formatTime(asset.last_seen_at)}</span><span><ChevronRight size={17} /></span>
  </button>;
}

function attributeNumber(asset: Asset, key: string): number {
  const value = asset.attributes?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function entraConnectionLabel(connectionId: string): string {
  const tenantId = connectionId.startsWith("entra:") ? connectionId.slice("entra:".length) : connectionId;
  return `Tenant ${tenantId}`;
}

function RuntimeActivityPage({
  summary,
  activities,
  includeFixtures,
  navigation,
  onToggleFixtures,
  onOpenActivity,
}: {
  summary: RuntimeActivitySummary;
  activities: RuntimeActivity[];
  includeFixtures: boolean;
  navigation: FilterNavigation;
  onToggleFixtures: () => void;
  onOpenActivity: (id: string) => void;
}) {
  const search = navigation.values.q ?? "";
  const category = navigation.values.category ?? "all";
  const outcome = navigation.values.outcome ?? "all";
  const filtered = useMemo(() => activities.filter((item) => {
    const haystack = `${item.title} ${item.activity_name} ${item.actor_name ?? ""} ${item.actor_uid ?? ""} ${item.provider}`.toLowerCase();
    return haystack.includes(search.toLowerCase()) &&
      (category === "all" || item.category === category) &&
      (outcome === "all" || item.outcome === outcome);
  }), [activities, category, outcome, search]);

  return <div className="page-stack runtime-page">
    <section className="page-intro"><div><span className="eyebrow">OBSERVED BEHAVIOR</span><h2>See how AI is actually used.</h2><p>Provider-neutral model, agent, tool, and AI application activity—kept separate from detections and issues.</p></div><div className="result-count"><strong>{summary.last_24h}</strong><span>observed in the last 24 hours</span><small>{summary.total} retained activity records</small></div></section>
    <section className="runtime-metric-grid">
      <RuntimeMetric icon={Activity} tone="total" label="Total activity" value={summary.total} detail="immutable observations" />
      <RuntimeMetric icon={Clock3} tone="recent" label="Last 24 hours" value={summary.last_24h} detail="recent observations" />
      <RuntimeMetric icon={Waypoints} tone="providers" label="Providers" value={summary.providers} detail="active telemetry sources" />
      <RuntimeMetric icon={CircleAlert} tone="failures" label="Failed activity" value={summary.failures} detail="outcomes, not findings" />
    </section>
    {summary.fixture_total > 0 && <section className="runtime-fixture-callout">
      <div><CircleHelp size={20} /><span><strong>{summary.fixture_total} transparent demo {summary.fixture_total === 1 ? "record" : "records"} {includeFixtures ? "included" : "excluded"}</strong><small>Fixture observations are clearly marked and never counted as live unless you choose to include them.</small></span></div>
      <button onClick={onToggleFixtures}>{includeFixtures ? "Hide demo data" : "Include demo data"}</button>
    </section>}
    <section className="panel runtime-panel">
      <div className="filterbar">
        <label className="search-field"><Search size={18} /><input value={search} onChange={(event) => navigation.set("q", event.target.value, "", "replace")} placeholder="Search activity, actor, or provider…" /></label>
        <label className="select-field"><Activity size={16} /><select value={category} onChange={(event) => navigation.set("category", event.target.value, "all")}><option value="all">All activity types</option>{Object.entries(ACTIVITY_META).map(([value, item]) => <option key={value} value={value}>{item.label}</option>)}</select></label>
        <label className="select-field"><ListFilter size={16} /><select value={outcome} onChange={(event) => navigation.set("outcome", event.target.value, "all")}><option value="all">All outcomes</option><option value="success">Success</option><option value="failure">Failure</option><option value="unknown">Unknown</option></select></label>
        {(search || category !== "all" || outcome !== "all") && <button className="clear-button" onClick={() => navigation.clear(["q", "category", "outcome"])}>Reset</button>}
      </div>
      <div className="runtime-table" role="table" aria-label="AI runtime activity">
        <div className="runtime-table-head" role="row"><span>Activity</span><span>Type</span><span>Outcome</span><span>Actor</span><span>Provider</span><span>Occurred</span><span /></div>
        {filtered.map((item) => <RuntimeActivityRow key={item.id} item={item} onClick={() => onOpenActivity(item.id)} />)}
        {filtered.length === 0 && <div className="empty-state"><Activity /><strong>{activities.length === 0 ? "No runtime activity has been imported" : "No activity matches these filters"}</strong><span>{activities.length === 0 ? "Import a bounded provider activity export or run the transparent demo seed." : "Reset the filters to see the full activity stream."}</span></div>}
      </div>
    </section>
    <p className="fixture-note"><ShieldCheck size={15} /> Runtime activity is an observation, not a detection or issue. Denali makes no risk claim until a separate rule evaluates the evidence.</p>
  </div>;
}

function RuntimeMetric({ icon: Icon, tone, label, value, detail }: { icon: LucideIcon; tone: string; label: string; value: number | string; detail: string }) {
  return <div className={`runtime-metric ${tone}`}><span><Icon /></span><div><small>{label}</small><strong>{value}</strong><em>{detail}</em></div></div>;
}

function RuntimeActivityRow({ item, onClick }: { item: RuntimeActivity; onClick: () => void }) {
  const activity = ACTIVITY_META[item.category];
  const Icon = activity.icon;
  return <button className="runtime-table-row" role="row" onClick={onClick}>
    <span className="runtime-title-cell"><span className={`asset-icon ${activity.color}`}><Icon /></span><span><strong>{item.title}</strong><small>{item.activity_name} · {item.entity_count} {item.entity_count === 1 ? "entity" : "entities"}</small></span></span>
    <span>{activity.label}</span>
    <span><span className={`outcome-badge ${item.outcome}`}>{titleCase(item.outcome)}</span></span>
    <span className="runtime-actor"><strong>{item.actor_name ?? shortKey(item.actor_uid ?? "Unknown actor")}</strong><small>{item.actor_asset_id ? "Inventory correlated" : "Reference only"}</small></span>
    <span>{titleCase(item.provider)}</span>
    <span>{formatTime(item.occurred_at)}</span><span><ChevronRight size={17} /></span>
  </button>;
}

function RuntimeActivityDrawer({ activityId, tab, onTab, onClose, onOpenAsset }: { activityId: string; tab: "overview" | "evidence"; onTab: (tab: string) => void; onClose: () => void; onOpenAsset: (id: string) => void }) {
  const [detail, setDetail] = useState<RuntimeActivityDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDetail(null); setError(null);
    api.activityDetail(activityId).then(setDetail).catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load runtime activity"));
  }, [activityId]);

  const activity = detail ? ACTIVITY_META[detail.category] : null;
  const Icon = activity?.icon ?? Activity;
  const correlated = detail?.entities.filter((entity) => entity.asset_id !== null).length ?? 0;
  return <div className="drawer-layer"><button className="drawer-scrim" onClick={onClose} aria-label="Close runtime activity detail" /><aside className="resource-drawer runtime-drawer" aria-label="Runtime activity detail">
    {!detail && !error ? <LoadingState compact /> : error ? <ErrorState message={error} subject="runtime activity" /> : detail && activity && <>
      <div className="drawer-header runtime-drawer-header"><button className="drawer-close" onClick={onClose}><X /></button><span className={`asset-icon large ${activity.color}`}><Icon /></span><div><span>{activity.label}</span><h2>{detail.title}</h2><p>{detail.provider} · {detail.source_uid}</p></div><span className={`outcome-badge ${detail.outcome}`}>{titleCase(detail.outcome)}</span></div>
      <div className="finding-summary-strip"><span><strong>{formatTime(detail.occurred_at)}</strong></span><span><strong>{detail.entities.length}</strong> observed entities</span><span><strong>{correlated}</strong> inventory correlated</span><span>{titleCase(detail.provider)}</span></div>
      <div className="drawer-tabs">{(["overview", "evidence"] as const).map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => onTab(item)}>{titleCase(item)}{item === "overview" && <small>{detail.entities.length}</small>}</button>)}</div>
      <div className="drawer-content">{tab === "overview" ? <RuntimeActivityOverview detail={detail} onOpenAsset={onOpenAsset} /> : <RuntimeActivityEvidence detail={detail} />}</div>
    </>}
  </aside></div>;
}

function RuntimeActivityOverview({ detail, onOpenAsset }: { detail: RuntimeActivityDetail; onOpenAsset: (id: string) => void }) {
  return <div className="detail-stack">
    <div className="runtime-observation"><span>WHAT DENALI OBSERVED</span><p>{detail.title}</p><small>This record reports source activity and outcome only. It is not a security verdict.</small></div>
    <DetailSection title="Observed entities"><div className="runtime-entity-list">{detail.entities.map((entity) => {
      const content = <><span className={`asset-icon ${entity.asset_id ? "green" : "slate"}`}>{entity.asset_id ? <Link2 /> : <CircleHelp />}</span><span><strong>{entity.asset_display_name ?? entity.display_name ?? shortKey(entity.external_uid)}</strong><small>{titleCase(entity.role)} · {entity.asset_id ? `${titleCase(entity.correlation)} · ${Math.round(entity.confidence * 100)}%` : "Reference only · no inventory link"}</small><code>{entity.external_uid}</code></span><em>{entity.asset_id ? "Inventory correlated" : "Unresolved"}</em>{entity.asset_id && <ChevronRight />}</>;
      return entity.asset_id ? <button key={`${entity.position}-${entity.external_uid}`} onClick={() => onOpenAsset(entity.asset_id!)}>{content}</button> : <div key={`${entity.position}-${entity.external_uid}`}>{content}</div>;
    })}</div></DetailSection>
    <DetailSection title="Activity properties"><div className="property-grid"><Property label="Activity" value={detail.activity_name} /><Property label="Outcome" value={titleCase(detail.outcome)} /><Property label="Provider" value={titleCase(detail.provider)} /><Property label="Region" value={detail.region ?? "Not provided"} /><Property label="Account" value={detail.account_uid ?? "Not provided"} mono /><Property label="Scope" value={detail.scope_key} mono /><Property label="Session" value={detail.session_uid ?? "Not provided"} mono /><Property label="Trace" value={detail.trace_uid ?? "Not provided"} mono /></div></DetailSection>
  </div>;
}

function RuntimeActivityEvidence({ detail }: { detail: RuntimeActivityDetail }) {
  return <div className="detail-stack"><div className="evidence-principle"><ShieldCheck /><div><strong>Source evidence remains bounded and intact</strong><p>The adapter retains a locator and selected source fields. Runtime references never create inventory assets.</p></div></div><DetailSection title="Evidence"><div className="evidence-card"><Property label="Source type" value={detail.evidence.source_type} /><Property label="Observed at" value={formatTime(detail.evidence.observed_at)} /><Property label="Locator" value={detail.evidence.locator} mono /><Property label="Source UID" value={detail.source_uid} mono /><details open><summary>Normalized evidence payload</summary><pre>{JSON.stringify(detail.evidence.payload, null, 2)}</pre></details></div></DetailSection>{Object.keys(detail.attributes).length > 0 && <DetailSection title="Source metadata"><div className="attribute-list">{Object.entries(detail.attributes).map(([key, value]) => <div key={key}><span>{titleCase(key)}</span><strong>{typeof value === "object" ? JSON.stringify(value) : String(value)}</strong></div>)}</div></DetailSection>}</div>;
}

function RuntimeDetectionsPage({
  summary,
  detections,
  evaluations,
  coverage,
  navigation,
  onOpenDetection,
}: {
  summary: RuntimeDetectionSummary;
  detections: RuntimeDetection[];
  evaluations: RuntimeDetectionEvaluation[];
  coverage: Coverage[];
  navigation: FilterNavigation;
  onOpenDetection: (id: string) => void;
}) {
  const search = navigation.values.q ?? "";
  const severity = navigation.values.severity ?? "all";
  const state = navigation.values.state ?? "open";
  const filtered = useMemo(() => detections.filter((item) => {
    const actor = stringValue(item.attributes.actor_display_name) ?? stringValue(item.attributes.actor_uid) ?? "";
    const haystack = `${item.title} ${item.rule_uid} ${item.description} ${actor}`.toLowerCase();
    return haystack.includes(search.toLowerCase()) &&
      (severity === "all" || item.severity === severity) &&
      (state === "all" || item.state === state);
  }), [detections, search, severity, state]);
  const applicableEvaluations = useMemo(
    () => applicableDetectionEvaluations(evaluations, detections, coverage),
    [coverage, detections, evaluations],
  );
  const complete = applicableEvaluations.filter((item) => item.state === "complete").length;

  return <div className="page-stack detections-page">
    <section className="page-intro"><div><span className="eyebrow">EVALUATED BEHAVIOR</span><h2>Investigate behavior that crossed an explicit threshold.</h2><p>Evidence-led detections derived from immutable runtime observations. A detection is a reviewable conclusion, not a confirmed incident.</p></div><div className="result-count"><strong>{summary.by_state.open ?? 0}</strong><span>open runtime detections</span><small>{applicableEvaluations.length} applicable rules evaluated</small></div></section>
    <section className="runtime-metric-grid">
      <RuntimeMetric icon={Gauge} tone="total" label="Open detections" value={summary.by_state.open ?? 0} detail="evaluated conclusions" />
      <RuntimeMetric icon={CircleAlert} tone="failures" label="High severity" value={summary.open_by_severity.high ?? 0} detail="open detections" />
      <RuntimeMetric icon={Activity} tone="recent" label="Medium severity" value={summary.open_by_severity.medium ?? 0} detail="open detections" />
      <RuntimeMetric icon={ShieldCheck} tone="providers" label="Applicable rule coverage" value={applicableEvaluations.length === 0 ? "N/A" : complete} detail={applicableEvaluations.length === 0 ? "No rules apply to collected sources" : `of ${applicableEvaluations.length} rule evaluations complete`} />
    </section>
    <section className="detection-coverage-grid" aria-label="Detection rule coverage">
      {applicableEvaluations.map((item) => <div className={`detection-coverage-card ${item.state}`} key={item.rule_uid}><span className="detection-coverage-icon">{item.state === "complete" ? <CircleCheck /> : <CircleAlert />}</span><div><strong>{detectionRuleName(item.rule_uid)}</strong><small>{item.rule_uid}</small><p>{item.detail ?? `${item.confirmed_detections} confirmed; ${item.incomplete_candidates} incomplete candidates.`}</p></div><span className="detection-coverage-state">{titleCase(item.state)}</span></div>)}
      {applicableEvaluations.length === 0 && <div className="lineage-trust-banner detection-applicability-empty"><CircleHelp /><div><strong>No runtime detection rules apply to the collected sources</strong><p>Connect a supported activity source to evaluate its bounded behavior rules. This is an applicability boundary, not evidence that runtime risk is absent.</p></div><span>NOT APPLICABLE</span></div>}
    </section>
    <section className="panel detections-panel">
      <div className="filterbar">
        <label className="search-field"><Search size={18} /><input value={search} onChange={(event) => navigation.set("q", event.target.value, "", "replace")} placeholder="Search detection, actor, or rule…" /></label>
        <label className="select-field"><CircleAlert size={16} /><select value={severity} onChange={(event) => navigation.set("severity", event.target.value, "all")}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
        <label className="select-field"><ListFilter size={16} /><select value={state} onChange={(event) => navigation.set("state", event.target.value, "open")}><option value="all">All states</option><option value="open">Open</option><option value="resolved">Resolved</option><option value="unknown">Unknown</option></select></label>
        {(search || severity !== "all" || state !== "open") && <button className="clear-button" onClick={() => navigation.clear(["q", "severity", "state"])}>Reset</button>}
      </div>
      <div className="detections-table" role="table" aria-label="AI runtime detections">
        <div className="detections-table-head" role="row"><span>Detection</span><span>Severity</span><span>State</span><span>Evidence</span><span>Actor</span><span>Last seen</span><span /></div>
        {filtered.map((item) => <RuntimeDetectionRow key={item.id} item={item} onClick={() => onOpenDetection(item.id)} />)}
        {filtered.length === 0 && <div className="empty-state"><Gauge /><strong>{detections.length === 0 ? "No runtime behavior has crossed a detection threshold" : "No detections match these filters"}</strong><span>{detections.length === 0 ? "Review rule coverage before interpreting this as no risk." : "Reset the filters to see all evaluated detections."}</span></div>}
      </div>
    </section>
    <p className="fixture-note"><ShieldCheck size={15} /> Detections cite source activity and exact inventory assertions. They do not promote an observation into a confirmed incident.</p>
  </div>;
}

function RuntimeDetectionRow({ item, onClick }: { item: RuntimeDetection; onClick: () => void }) {
  const actor = stringValue(item.attributes.actor_display_name) ?? stringValue(item.attributes.actor_uid) ?? "Not provided";
  return <button className="detections-table-row" role="row" onClick={onClick}>
    <span className="detection-title-cell"><span className="asset-icon coral"><Gauge /></span><span><strong>{item.title}</strong><small>{item.rule_uid}</small></span></span>
    <span><span className={`severity-badge ${item.severity}`}>{titleCase(item.severity)}</span></span>
    <span><span className={`finding-state ${item.state}`}>{titleCase(item.state)}</span></span>
    <span className="detection-evidence-count"><strong>{item.activity_count}</strong> activities<small>{item.asset_count} exact assets</small></span>
    <span className="detection-actor"><strong>{actor}</strong><small>{Math.round(item.confidence * 100)}% evidence confidence</small></span>
    <span>{formatTime(item.last_seen_at)}</span><span><ChevronRight size={17} /></span>
  </button>;
}

function RuntimeDetectionDrawer({ detectionId, tab, onTab, onClose, onOpenActivity, onOpenAsset }: { detectionId: string; tab: DetectionDetailTab; onTab: (tab: string) => void; onClose: () => void; onOpenActivity: (id: string) => void; onOpenAsset: (id: string) => void }) {
  const [detail, setDetail] = useState<RuntimeDetectionDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setDetail(null); setError(null);
    api.detection(detectionId).then(setDetail).catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load runtime detection"));
  }, [detectionId]);
  return <div className="drawer-layer"><button className="drawer-scrim" onClick={onClose} aria-label="Close runtime detection detail" /><aside className="resource-drawer detection-drawer" aria-label="Runtime detection detail">
    {!detail && !error ? <LoadingState compact /> : error ? <ErrorState message={error} subject="runtime detection" /> : detail && <>
      <div className="drawer-header detection-drawer-header"><button className="drawer-close" onClick={onClose}><X /></button><span className="asset-icon large coral"><Gauge /></span><div><span>BEHAVIOR DETECTION</span><h2>{detail.title}</h2><p>{detail.rule_uid}</p></div><span className={`severity-badge ${detail.severity}`}>{titleCase(detail.severity)}</span></div>
      <div className="finding-summary-strip"><span className={`finding-state ${detail.state}`}>{titleCase(detail.state)}</span><span><strong>{Math.round(detail.confidence * 100)}%</strong> evidence confidence</span><span><strong>{detail.activities.length}</strong> activities</span><span><strong>{detail.assets.length}</strong> exact assets</span><span>Last seen <strong>{formatTime(detail.last_seen_at)}</strong></span></div>
      <div className="drawer-tabs">{(["overview", "evidence"] as const).map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => onTab(item)}>{titleCase(item)}{item === "evidence" && <small>{detail.activities.length + detail.assets.length}</small>}</button>)}</div>
      <div className="drawer-content">{tab === "overview" ? <RuntimeDetectionOverview detail={detail} onOpenAsset={onOpenAsset} /> : <RuntimeDetectionEvidence detail={detail} onOpenActivity={onOpenActivity} onOpenAsset={onOpenAsset} />}</div>
    </>}
  </aside></div>;
}

function RuntimeDetectionOverview({ detail, onOpenAsset }: { detail: RuntimeDetectionDetail; onOpenAsset: (id: string) => void }) {
  return <div className="detail-stack">
    <div className="runtime-observation"><span>WHAT DENALI EVALUATED</span><p>{detail.description}</p><small>This conclusion crossed the named rule threshold. It is not a confirmed compromise or proof of malicious intent.</small></div>
    <DetailSection title="Risk and limits"><p className="finding-copy">{detail.risk}</p></DetailSection>
    <DetailSection title="Investigation guidance"><p className="finding-copy">{detail.investigation_guidance}</p></DetailSection>
    <DetailSection title="Affected inventory"><div className="affected-list">{detail.assets.map((asset) => <button key={asset.id} onClick={() => onOpenAsset(asset.id)}><span className={`asset-icon ${meta(asset.kind).color}`}>{(() => { const Icon = meta(asset.kind).icon; return <Icon />; })()}</span><span><strong>{asset.display_name}</strong><small>{meta(asset.kind).label} · {titleCase(asset.role)} · {titleCase(asset.assertion_type)}</small><code>{asset.natural_key}</code></span><em>{Math.round(asset.confidence * 100)}% confidence</em><ChevronRight /></button>)}</div></DetailSection>
    <DetailSection title="Detection properties"><div className="property-grid"><Property label="Rule" value={detail.rule_uid} mono /><Property label="State" value={titleCase(detail.state)} /><Property label="First seen" value={formatTime(detail.first_seen_at)} /><Property label="Last evaluated" value={formatTime(detail.last_evaluated_at)} />{Object.entries(detail.attributes).map(([key, value]) => <Property key={key} label={titleCase(key)} value={typeof value === "object" ? JSON.stringify(value) : String(value)} />)}</div></DetailSection>
  </div>;
}

function RuntimeDetectionEvidence({ detail, onOpenActivity, onOpenAsset }: { detail: RuntimeDetectionDetail; onOpenActivity: (id: string) => void; onOpenAsset: (id: string) => void }) {
  return <div className="detail-stack">
    <div className="evidence-principle"><ShieldCheck /><div><strong>{detail.activities.length + detail.assets.length} independent evidence links</strong><p>The detection stores references to immutable activity and exact inventory assertions; it does not copy or invent their evidence.</p></div></div>
    <DetailSection title="Runtime activity evidence"><div className="detection-evidence-list">{detail.activities.map((activity) => <button key={activity.id} onClick={() => onOpenActivity(activity.id)}><span className="asset-icon violet"><Activity /></span><span><strong>{activity.title}</strong><small>{titleCase(activity.role)} · {formatTime(activity.occurred_at)} · {titleCase(activity.outcome)}</small><code>{activity.evidence.source_type} · {activity.evidence.locator}</code></span><ChevronRight /></button>)}</div></DetailSection>
    <DetailSection title="Inventory assertion evidence"><div className="detection-evidence-list">{detail.assets.map((asset) => <button key={asset.id} onClick={() => onOpenAsset(asset.id)}><span className={`asset-icon ${meta(asset.kind).color}`}>{(() => { const Icon = meta(asset.kind).icon; return <Icon />; })()}</span><span><strong>{asset.display_name}</strong><small>{titleCase(asset.role)} · {titleCase(asset.assertion_type)} · {Math.round(asset.confidence * 100)}%</small><code>{asset.evidence.source_type} · {asset.evidence.locator}</code></span><ChevronRight /></button>)}</div></DetailSection>
  </div>;
}

function detectionRuleName(ruleUid: string) {
  if (ruleUid === "DENALI-RUNTIME-ENTRA-FAILURES-001") return "Repeated failed access to an AI application";
  if (ruleUid === "DENALI-RUNTIME-ENTRA-CONSENT-001") return "Consent changed for an unreviewed AI application";
  return titleCase(ruleUid);
}

const AWS_CONNECTION_SCOPES = [
  { id: "aws.bedrock_agents", label: "Bedrock Agents Classic", detail: "Agents and guardrails" },
  { id: "aws.agentcore", label: "Amazon Bedrock AgentCore", detail: "Runtimes, gateways, identities, and memory metadata" },
  { id: "aws.bedrock_activity", label: "Bedrock management activity", detail: "Bounded CloudTrail event history" },
  { id: "aws.bedrock_logging", label: "Invocation logging configuration", detail: "Configuration presence, never prompts or responses" },
  { id: "aws.code_to_cloud", label: "Code-to-cloud deployments", detail: "Lambda, ECS, EKS, and SageMaker endpoint identities and runtime roles" },
];

const AZURE_CONNECTION_SCOPES = [
  { id: "azure.ai_services", label: "Azure AI services", detail: "AI service accounts and Azure AI Search" },
  { id: "azure.ai_platform", label: "Azure AI platform", detail: "Machine Learning workspaces and Bot Service" },
  { id: "azure.ai_activity", label: "Azure AI management activity", detail: "Subscription Activity Log metadata; no prompts or responses" },
  { id: "azure.code_to_cloud", label: "Code-to-cloud deployments", detail: "Container Apps, Function Apps, and AKS cluster identities, revisions, images, and managed identities" },
];

const GCP_CONNECTION_SCOPES = [
  { id: "gcp.vertex_ai", label: "Vertex AI", detail: "Runtime, model, dataset, pipeline, and notebook resources" },
  { id: "gcp.agent_builder", label: "Agent Builder and Dialogflow", detail: "Discovery Engine and conversational agent resources" },
  { id: "gcp.ai_activity", label: "Google Cloud AI management activity", detail: "Cloud Audit Log metadata; no prompts or responses" },
  { id: "gcp.code_to_cloud", label: "Code-to-cloud deployments", detail: "Cloud Run, Cloud Run functions, and GKE cluster identities, revisions, images, and service accounts" },
];

const GITHUB_CONNECTION_SCOPES = [
  { id: "github.repository_metadata", label: "Repository metadata", detail: "Immutable repository identity and basic metadata" },
  { id: "github.repository_contents", label: "Source revision access", detail: "Read the default Git revision; no source writes" },
  { id: "github.actions_workflows", label: "GitHub Actions workflows", detail: "Workflow inventory only; no workflow runs, secrets, or writes" },
];

function connectionScopes(provider: "aws" | "azure" | "gcp" | "github") {
  return provider === "aws" ? AWS_CONNECTION_SCOPES
    : provider === "azure" ? AZURE_CONNECTION_SCOPES
      : provider === "gcp" ? GCP_CONNECTION_SCOPES
        : GITHUB_CONNECTION_SCOPES;
}

function ConnectionsPage({
  connections,
  selectedId,
  showCreate,
  navigation,
  onSelect,
  onShowCreate,
  onChanged,
  azureConsentReturn,
  githubSetupReturn,
  canWrite,
}: {
  connections: Connection[];
  selectedId?: string;
  showCreate: boolean;
  navigation: FilterNavigation;
  onSelect: (id: string, mode?: "push" | "replace") => void;
  onShowCreate: (visible: boolean) => void;
  onChanged: () => Promise<void>;
  azureConsentReturn: AzureConsentReturn | null;
  githubSetupReturn: GitHubSetupReturn | null;
  canWrite: boolean;
}) {
  const provider = (["aws", "azure", "gcp", "github"] as const).includes(navigation.values.provider as "aws" | "azure" | "gcp" | "github")
    ? navigation.values.provider as "aws" | "azure" | "gcp" | "github"
    : "aws";
  const [displayName, setDisplayName] = useState("");
  const [accountId, setAccountId] = useState("");
  const [partition, setPartition] = useState<AwsConnectionCreate["partition"]>("aws");
  const [deploymentRegion, setDeploymentRegion] = useState("us-east-1");
  const [coverageMode, setCoverageMode] = useState<AwsConnectionCreate["coverage_mode"]>("automatic");
  const [regions, setRegions] = useState("us-east-1");
  const [scopes, setScopes] = useState(() => connectionScopes(provider).map((scope) => scope.id));
  const [azureTenantId, setAzureTenantId] = useState("");
  const [azureLaunches, setAzureLaunches] = useState<Record<string, AzureSetupLaunch>>({});
  const [azureCompletionCode, setAzureCompletionCode] = useState<Record<string, string>>({});
  const [gcpLaunches, setGcpLaunches] = useState<Record<string, GcpSetupLaunch>>({});
  const [gcpCompletionCode, setGcpCompletionCode] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const selected = connections.find((connection) => connection.id === selectedId) ?? connections[0];

  useEffect(() => {
    setScopes(connectionScopes(provider).map((scope) => scope.id));
  }, [provider]);

  useEffect(() => {
    if (selected && selected.id !== selectedId) onSelect(selected.id, "replace");
    if (!selected && selectedId) onSelect("", "replace");
  }, [onSelect, selected, selectedId]);

  function selectProvider(next: "aws" | "azure" | "gcp" | "github") {
    navigation.set("provider", next, "aws");
  }

  async function createConnection(event: React.FormEvent) {
    event.preventDefault();
    setBusy("create");
    setActionError(null);
    try {
      const payload: AwsConnectionCreate | AzureConnectionCreate | GcpConnectionCreate | GitHubConnectionCreate = provider === "aws" ? {
          provider: "aws",
          display_name: displayName,
          account_id: accountId,
          partition,
          deployment_region: deploymentRegion,
          coverage_mode: coverageMode,
          regions: coverageMode === "selected" ? regions.split(",").map((region) => region.trim()).filter(Boolean) : [],
          declared_scopes: scopes,
        } : provider === "azure" ? {
          provider: "azure",
          display_name: displayName,
          tenant_id: azureTenantId,
          cloud: "AzureCloud",
          declared_scopes: scopes,
        } : provider === "gcp" ? {
          provider: "gcp",
          display_name: displayName,
          declared_scopes: scopes,
        } : {
          provider: "github",
          display_name: displayName,
          declared_scopes: scopes,
        };
      const created = await api.createConnection(payload);
      await onChanged();
      onSelect(created.id);
      setDisplayName("");
      setAccountId("");
      setAzureTenantId("");
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to create connection");
    } finally {
      setBusy(null);
    }
  }

  async function validateConnection(connection: Connection) {
    setBusy(`validate:${connection.id}`);
    setActionError(null);
    try {
      await api.validateConnection(connection.id);
      await waitForValidation(connection, 150);
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to validate connection");
    } finally {
      setBusy(null);
    }
  }

  async function waitForValidation(connection: Connection, maxAttempts: number) {
    const previousValidation = connection.last_validated_at ?? null;
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 2000));
      const current = await api.connection(connection.id);
      if (current.validation_state === "running") continue;
      if (current.last_validated_at !== previousValidation) {
        await onChanged();
        return;
      }
      throw new Error("Validation stopped before a result was recorded.");
    }
    throw new Error("Validation is still running. Refresh shortly to see its result.");
  }

  async function launchConnection(connection: Connection) {
    const launchWindow = window.open("about:blank", "_blank");
    if (!launchWindow) {
      setActionError("Allow pop-ups for Denali, then select Launch in AWS again.");
      return;
    }
    launchWindow.opener = null;
    let navigated = false;
    setBusy(`launch:${connection.id}`);
    setActionError(null);
    try {
      const launch = await api.launchCloudFormation(connection.id);
      launchWindow.location.replace(launch.launch_url);
      navigated = true;
      await waitForValidation(connection, 525);
    } catch (cause) {
      if (!navigated) launchWindow.close();
      setActionError(cause instanceof Error ? cause.message : "Unable to launch AWS");
    } finally {
      setBusy(null);
    }
  }

  async function downloadCloudFormation(connection: Connection) {
    setBusy(`download:${connection.id}`);
    setActionError(null);
    try {
      const template = await api.cloudFormationTemplate(connection.id);
      const url = URL.createObjectURL(template);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `denali-${connection.configuration.account_id ?? connection.id}.yaml`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to download CloudFormation template");
    } finally {
      setBusy(null);
    }
  }

  async function prepareAzureSetup(connection: Connection) {
    setBusy(`launch:${connection.id}`);
    setActionError(null);
    try {
      const launch = await api.launchAzureSetup(connection.id);
      setAzureLaunches((current) => ({ ...current, [connection.id]: launch }));
      await onChanged();
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to prepare Azure setup");
    } finally {
      setBusy(null);
    }
  }

  async function completeAzureSetup(connection: Connection) {
    const completionCode = azureCompletionCode[connection.id]?.trim();
    if (!completionCode) {
      setActionError("Paste the completion code printed by the Azure setup script.");
      return;
    }
    setBusy(`complete:${connection.id}`);
    setActionError(null);
    try {
      await api.completeAzureSetup(connection.id, completionCode);
      await waitForValidation(connection, 525);
      setAzureCompletionCode((current) => ({ ...current, [connection.id]: "" }));
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to complete Azure setup");
    } finally {
      setBusy(null);
    }
  }

  async function prepareGcpSetup(connection: Connection) {
    setBusy(`launch:${connection.id}`);
    setActionError(null);
    try {
      const launch = await api.launchGcpSetup(connection.id);
      setGcpLaunches((current) => ({ ...current, [connection.id]: launch }));
      await onChanged();
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to prepare Google Cloud setup");
    } finally {
      setBusy(null);
    }
  }

  async function completeGcpSetup(connection: Connection) {
    const completionCode = gcpCompletionCode[connection.id]?.trim();
    if (!completionCode) {
      setActionError("Paste the completion code printed by the Google Cloud setup script.");
      return;
    }
    setBusy(`complete:${connection.id}`);
    setActionError(null);
    try {
      await api.completeGcpSetup(connection.id, completionCode);
      await waitForValidation(connection, 525);
      setGcpCompletionCode((current) => ({ ...current, [connection.id]: "" }));
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to complete Google Cloud setup");
    } finally {
      setBusy(null);
    }
  }

  async function collectGcpDeployments(connection: Connection) {
    setBusy(`collect-gcp:${connection.id}`);
    setActionError(null);
    const previousCompletion = connection.last_deployment_collection?.completed_at ?? null;
    try {
      await api.collectGcpDeployments(connection.id);
      for (let attempt = 0; attempt < 525; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 2000));
        const current = await api.connection(connection.id);
        if (current.deployment_collection_state === "running") continue;
        if (current.last_deployment_collection?.completed_at !== previousCompletion) {
          await onChanged();
          return;
        }
        throw new Error("Deployment collection stopped before a result was recorded.");
      }
      throw new Error("Deployment collection is still running. Refresh shortly to see its result.");
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to collect GCP deployments");
    } finally {
      setBusy(null);
    }
  }

  async function collectAzureDeployments(connection: Connection) {
    setBusy(`collect-azure:${connection.id}`);
    setActionError(null);
    const previousCompletion = connection.last_deployment_collection?.completed_at ?? null;
    try {
      await api.collectAzureDeployments(connection.id);
      for (let attempt = 0; attempt < 525; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 2000));
        const current = await api.connection(connection.id);
        if (current.deployment_collection_state === "running") continue;
        if (current.last_deployment_collection?.completed_at !== previousCompletion) {
          await onChanged();
          return;
        }
        throw new Error("Deployment collection stopped before a result was recorded.");
      }
      throw new Error("Deployment collection is still running. Refresh shortly to see its result.");
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to collect Azure deployments");
    } finally {
      setBusy(null);
    }
  }

  async function collectAwsDeployments(connection: Connection) {
    setBusy(`collect-aws:${connection.id}`);
    setActionError(null);
    const previousCompletion = connection.last_deployment_collection?.completed_at ?? null;
    try {
      await api.collectAwsDeployments(connection.id);
      for (let attempt = 0; attempt < 525; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 2000));
        const current = await api.connection(connection.id);
        if (current.deployment_collection_state === "running") continue;
        if (current.last_deployment_collection?.completed_at !== previousCompletion) {
          await onChanged();
          return;
        }
        throw new Error("Deployment collection stopped before a result was recorded.");
      }
      throw new Error("Deployment collection is still running. Refresh shortly to see its result.");
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to collect AWS deployments");
    } finally {
      setBusy(null);
    }
  }

  async function prepareGitHubSetup(connection: Connection) {
    setBusy(`launch:${connection.id}`);
    setActionError(null);
    try {
      const launch = await api.launchGitHubSetup(connection.id);
      window.location.assign(launch.install_url);
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to open GitHub App setup");
      setBusy(null);
    }
  }

  async function collectGitHubSource(connection: Connection) {
    setBusy(`collect:${connection.id}`);
    setActionError(null);
    const previousCompletion = connection.last_source_collection?.completed_at ?? null;
    try {
      await api.collectGitHubSource(connection.id);
      for (let attempt = 0; attempt < 525; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 2000));
        const current = await api.connection(connection.id);
        if (current.source_collection_state === "running") continue;
        if (current.last_source_collection?.completed_at !== previousCompletion) {
          await onChanged();
          return;
        }
        throw new Error("Source collection stopped before a result was recorded.");
      }
      throw new Error("Source collection is still running. Refresh shortly to see its result.");
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to collect GitHub source");
    } finally {
      setBusy(null);
    }
  }

  async function disableConnection(connection: Connection) {
    if (!window.confirm(`Disable ${connection.display_name}? Scheduled collection must stop using this connection.`)) return;
    setBusy(`disable:${connection.id}`);
    setActionError(null);
    try {
      await api.disableConnection(connection.id);
      await onChanged();
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to disable connection");
    } finally {
      setBusy(null);
    }
  }

  async function deleteConnection(connection: Connection) {
    const confirmation = window.prompt(
      `Type “${connection.display_name}” to delete its configuration. Collected evidence is retained.`,
    );
    if (confirmation === null) return;
    setBusy(`delete:${connection.id}`);
    setActionError(null);
    try {
      await api.deleteConnection(connection.id, confirmation);
      await onChanged();
      onSelect("", "replace");
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Unable to delete connection");
    } finally {
      setBusy(null);
    }
  }

  function toggleScope(scopeId: string) {
    setScopes((current) => current.includes(scopeId)
      ? current.filter((item) => item !== scopeId)
      : [...current, scopeId]);
  }

  return <div className="page-stack connections-page">
    <section className="page-intro connection-intro">
      <div><span className="eyebrow">SELF-SERVICE ONBOARDING</span><h2>Connect evidence sources without handing Denali customer credentials.</h2><p>AWS uses assume-role; Azure and Google Cloud use provider-native, keyless identities; GitHub uses short-lived App installation tokens. Customers select exact cloud scopes or repositories, and every declared plane is validated separately.</p></div>
      {canWrite && <button className="primary-action" onClick={() => onShowCreate(!showCreate)}><Plus /> Add connection</button>}
    </section>
    {!canWrite && <section className="read-only-banner"><ShieldCheck /><div><strong>Read-only organization role</strong><span>An organization admin must create, validate, disable, or delete connections.</span></div></section>}
    <section className="connection-boundary"><ShieldCheck /><div><strong>Connection health is not a risk verdict.</strong><span>A healthy connection means the configured role and declared validation calls worked. It does not mean collection is complete, findings are absent, or the connected environment is safe.</span></div></section>
    {azureConsentReturn && <div className={`connection-consent-return ${azureConsentReturn.state}`}>
      {azureConsentReturn.state === "succeeded" ? <CircleCheck /> : <CircleAlert />}
      <span><strong>{azureConsentReturn.state === "succeeded" ? "Denali’s tenant identity is ready" : "Microsoft Entra could not add Denali to the tenant"}</strong><small>{azureConsentReturn.state === "succeeded" ? `Entra confirmed Denali’s enterprise application${azureConsentReturn.tenantId ? ` in tenant ${azureConsentReturn.tenantId}` : ""}. This step grants no subscription or Microsoft Graph access; selected-subscription Reader access is granted separately in Cloud Shell and verified by Denali.` : azureConsentReturn.detail}</small></span>
    </div>}
    {githubSetupReturn && <div className={`connection-consent-return ${githubSetupReturn.state}`}>
      {githubSetupReturn.state === "succeeded" ? <CircleCheck /> : <CircleAlert />}
      <span><strong>{githubSetupReturn.state === "succeeded" ? "GitHub App installation verified" : "GitHub App installation could not be verified"}</strong><small>{githubSetupReturn.state === "succeeded" ? "Denali confirmed the signed-in installer could access this exact installation, recorded its current repository IDs, discarded the temporary user token, and started read-only validation." : githubSetupReturn.detail ?? "Return to the connection and try the GitHub App setup again."}</small></span>
    </div>}
    {actionError && <div className="connection-error"><CircleAlert /><span>{actionError}</span></div>}
    {canWrite && showCreate && <form className="panel connection-create" onSubmit={(event) => void createConnection(event)}>
      <div className="connection-provider-picker"><button type="button" className={provider === "aws" ? "active" : ""} onClick={() => selectProvider("aws")}>Amazon Web Services</button><button type="button" className={provider === "azure" ? "active" : ""} onClick={() => selectProvider("azure")}>Microsoft Azure</button><button type="button" className={provider === "gcp" ? "active" : ""} onClick={() => selectProvider("gcp")}>Google Cloud</button><button type="button" className={provider === "github" ? "active" : ""} onClick={() => selectProvider("github")}>GitHub</button></div>
      <div className="connection-create-head"><div><span>NEW CONNECTION</span><h3>{provider === "aws" ? "Amazon Web Services" : provider === "azure" ? "Microsoft Azure" : provider === "gcp" ? "Google Cloud" : "GitHub"}</h3><p>{provider === "aws" ? "CloudFormation creates one read-only role with an external-ID trust condition. No access keys are created or stored." : provider === "azure" ? "Denali’s multi-tenant application receives Reader only on subscriptions you select in Azure Cloud Shell. No customer client secret is created or stored." : provider === "gcp" ? "Denali creates a unique keyless service account for this connection. Google Cloud Shell grants it bounded read roles only on projects you select; no customer key or user token is stored." : "Install Denali’s GitHub App on repositories you select. Denali uses short-lived, exact-repository installation tokens and never stores a personal access token or GitHub user token."}</p></div><span className="provider-mark">{provider === "aws" ? "AWS" : provider === "azure" ? "AZURE" : provider === "gcp" ? "GCP" : "GITHUB"}</span></div>
      <div className="connection-form-grid">
        <label><span>Connection name</span><input required maxLength={120} value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder={provider === "aws" ? "Production AWS" : provider === "azure" ? "Production Azure" : provider === "gcp" ? "Production Google Cloud" : "Production GitHub"} /></label>
        {provider === "aws" ? <>
        <label><span>AWS account ID</span><input required inputMode="numeric" pattern="[0-9]{12}" maxLength={12} value={accountId} onChange={(event) => setAccountId(event.target.value)} placeholder="123456789012" /></label>
        <label><span>Partition</span><select value={partition} onChange={(event) => setPartition(event.target.value as AwsConnectionCreate["partition"])}><option value="aws">Commercial AWS</option><option value="aws-us-gov">AWS GovCloud</option><option value="aws-cn">AWS China</option></select></label>
        <label><span>Preferred CloudFormation stack location</span><input required value={deploymentRegion} onChange={(event) => setDeploymentRegion(event.target.value)} placeholder="us-east-1" /><small>This plans where the stack is managed; it does not limit inventory coverage.</small></label>
        <label><span>Inventory region coverage</span><select value={coverageMode} onChange={(event) => setCoverageMode(event.target.value as AwsConnectionCreate["coverage_mode"])}><option value="automatic">All enabled regions (recommended)</option><option value="selected">Selected regions only</option></select><small>Automatic mode rediscovers enabled and opted-in regions on every validation.</small></label>
        {coverageMode === "selected" && <label><span>Selected inventory regions</span><input required value={regions} onChange={(event) => setRegions(event.target.value)} placeholder="us-east-1, us-west-2" /><small>Coverage outside this explicit allowlist will be reported as excluded.</small></label>}</> : provider === "azure" ? <>
        <label><span>Microsoft Entra tenant ID</span><input required pattern="[0-9a-fA-F-]{36}" maxLength={36} value={azureTenantId} onChange={(event) => setAzureTenantId(event.target.value)} placeholder="00000000-0000-0000-0000-000000000000" /><small>Cloud Shell will enumerate enabled subscriptions in this tenant and let you choose.</small></label>
        <label><span>Resource location coverage</span><input value="All locations in selected subscriptions" disabled /><small>Azure Resource Graph queries are subscription-wide; no single region limits coverage.</small></label></> : provider === "gcp" ? <>
        <label><span>Project selection</span><input value="Choose in Google Cloud Shell" disabled /><small>Cloud Shell enumerates active projects visible to your signed-in Google identity and lets you choose.</small></label>
        <label><span>Resource location coverage</span><input value="All locations in selected projects" disabled /><small>Cloud Asset Inventory queries are project-wide; no preferred region limits coverage.</small></label></> : <>
        <label><span>Repository selection</span><input value="Choose in GitHub" disabled /><small>GitHub’s installation page lets you select repositories in one user or organization account.</small></label>
        <label><span>Token boundary</span><input value="One exact repository per short-lived token" disabled /><small>Denali records immutable repository IDs and does not silently include repositories added later.</small></label></>}
      </div>
      <fieldset className="connection-scope-picker"><legend>Declared collection planes</legend>{(provider === "aws" ? AWS_CONNECTION_SCOPES : provider === "azure" ? AZURE_CONNECTION_SCOPES : provider === "gcp" ? GCP_CONNECTION_SCOPES : GITHUB_CONNECTION_SCOPES).map((scope) => <label key={scope.id}><input type="checkbox" checked={scopes.includes(scope.id)} onChange={() => toggleScope(scope.id)} /><span><strong>{scope.label}</strong><small>{scope.detail}</small></span></label>)}</fieldset>
      <div className="connection-form-actions"><button type="button" onClick={() => onShowCreate(false)}>Cancel</button><button className="primary-action" type="submit" disabled={busy === "create" || scopes.length === 0}>{busy === "create" ? "Creating…" : "Create onboarding plan"}</button></div>
    </form>}
    <div className="connections-layout">
      <section className="panel connection-list-panel">
        <PanelHeader eyebrow="SOURCES" title={`${connections.length} connection${connections.length === 1 ? "" : "s"}`} />
        <div className="connection-list">{connections.map((connection) => <button key={connection.id} className={selected?.id === connection.id ? "active" : ""} onClick={() => onSelect(connection.id)}><span className="connection-provider-icon"><CloudCog /></span><span><strong>{connection.display_name}</strong><small>{connection.provider === "aws" ? `${connection.configuration.account_id} · ${(connection.configuration.coverage_mode ?? "automatic") === "automatic" ? "all enabled regions" : (connection.configuration.regions ?? []).join(", ")}` : connection.provider === "azure" ? `${connection.configuration.tenant_id} · ${connection.configuration.subscriptions?.length ?? 0} selected subscriptions` : connection.provider === "gcp" ? `${connection.configuration.projects?.length ?? 0} selected projects` : `${connection.configuration.account_login ?? "not installed"} · ${connection.configuration.repositories?.length ?? 0} exact repositories`}</small></span><ConnectionHealth state={connection.health_state} /></button>)}{connections.length === 0 && <div className="empty-state"><CloudCog /><strong>No connections configured</strong><span>Create an AWS, Azure, Google Cloud, or GitHub onboarding plan to begin.</span></div>}</div>
      </section>
      {selected && <div className={canWrite ? "" : "read-only-detail"}><ConnectionDetail connection={selected} busy={busy} navigation={navigation} azureLaunch={azureLaunches[selected.id]} azureCompletionCode={azureCompletionCode[selected.id] ?? ""} onAzureCompletionCode={(value) => setAzureCompletionCode((current) => ({ ...current, [selected.id]: value }))} onPrepareAzure={() => void prepareAzureSetup(selected)} onCompleteAzure={() => void completeAzureSetup(selected)} onCollectAzure={() => void collectAzureDeployments(selected)} gcpLaunch={gcpLaunches[selected.id]} gcpCompletionCode={gcpCompletionCode[selected.id] ?? ""} onGcpCompletionCode={(value) => setGcpCompletionCode((current) => ({ ...current, [selected.id]: value }))} onPrepareGcp={() => void prepareGcpSetup(selected)} onCompleteGcp={() => void completeGcpSetup(selected)} onCollectGcp={() => void collectGcpDeployments(selected)} onCollectAws={() => void collectAwsDeployments(selected)} onPrepareGitHub={() => void prepareGitHubSetup(selected)} onCollectGitHub={() => void collectGitHubSource(selected)} onLaunch={() => void launchConnection(selected)} onDownload={() => void downloadCloudFormation(selected)} onValidate={() => void validateConnection(selected)} onDisable={() => void disableConnection(selected)} onDelete={() => void deleteConnection(selected)} /></div>}
    </div>
  </div>;
}

function ConnectionHealth({ state }: { state: Connection["health_state"] }) {
  const Icon = state === "healthy" ? CircleCheck : state === "partial" || state === "unknown" ? CircleHelp : CircleAlert;
  return <span className={`connection-health ${state}`}><Icon />{titleCase(state)}</span>;
}

function ConnectionDetail({ connection, busy, navigation, azureLaunch, azureCompletionCode, onAzureCompletionCode, onPrepareAzure, onCompleteAzure, onCollectAzure, gcpLaunch, gcpCompletionCode, onGcpCompletionCode, onPrepareGcp, onCompleteGcp, onCollectGcp, onCollectAws, onPrepareGitHub, onCollectGitHub, onLaunch, onDownload, onValidate, onDisable, onDelete }: { connection: Connection; busy: string | null; navigation: FilterNavigation; azureLaunch?: AzureSetupLaunch; azureCompletionCode: string; onAzureCompletionCode: (value: string) => void; onPrepareAzure: () => void; onCompleteAzure: () => void; onCollectAzure: () => void; gcpLaunch?: GcpSetupLaunch; gcpCompletionCode: string; onGcpCompletionCode: (value: string) => void; onPrepareGcp: () => void; onCompleteGcp: () => void; onCollectGcp: () => void; onCollectAws: () => void; onPrepareGitHub: () => void; onCollectGitHub: () => void; onLaunch: () => void; onDownload: () => void; onValidate: () => void; onDisable: () => void; onDelete: () => void }) {
  if (connection.provider === "azure") return <AzureConnectionDetail connection={connection} busy={busy} launch={azureLaunch} completionCode={azureCompletionCode} onCompletionCode={onAzureCompletionCode} onPrepare={onPrepareAzure} onComplete={onCompleteAzure} onCollect={onCollectAzure} onValidate={onValidate} onDisable={onDisable} onDelete={onDelete} />;
  if (connection.provider === "gcp") return <GcpConnectionDetail connection={connection} busy={busy} launch={gcpLaunch} completionCode={gcpCompletionCode} onCompletionCode={onGcpCompletionCode} onPrepare={onPrepareGcp} onComplete={onCompleteGcp} onCollect={onCollectGcp} onValidate={onValidate} onDisable={onDisable} onDelete={onDelete} />;
  if (connection.provider === "github") return <GitHubConnectionDetail connection={connection} busy={busy} navigation={navigation} onPrepare={onPrepareGitHub} onCollect={onCollectGitHub} onValidate={onValidate} onDisable={onDisable} onDelete={onDelete} />;
  const validation = connection.last_validation;
  const awsCredential = connection.credential_reference.type === "aws_assume_role" ? connection.credential_reference : null;
  const launching = busy === `launch:${connection.id}`;
  const validating = connection.validation_state === "running" || busy === `validate:${connection.id}` || launching;
  const validatedRole = validation?.credential_state === "passed";
  const collecting = connection.deployment_collection_state === "running" || busy === `collect-aws:${connection.id}`;
  const collection = connection.last_deployment_collection && "region_count" in connection.last_deployment_collection ? connection.last_deployment_collection : null;
  const collectionScopeSelected = connection.declared_scopes.includes("aws.code_to_cloud");
  const permissions = [...new Set(["ec2:DescribeRegions", ...connection.coverage_plan.flatMap((item) => item.permissions)])].sort();
  const regionDiscovery = validation?.results.find((result) => result.plane === "aws_region_discovery");
  const planeResults = validation?.results.filter((result) => result.plane !== "aws_region_discovery") ?? [];
  const planeSummaries = [...planeResults.reduce((summaries, result) => {
    const current = summaries.get(result.plane) ?? { label: result.label, total: 0, passed: 0, failed: 0, unknown: 0, notApplicable: 0 };
    current.total += 1;
    if (result.state === "passed") current.passed += 1;
    else if (result.state === "failed") current.failed += 1;
    else if (result.state === "not_applicable") current.notApplicable += 1;
    else current.unknown += 1;
    summaries.set(result.plane, current);
    return summaries;
  }, new Map<string, { label: string; total: number; passed: number; failed: number; unknown: number; notApplicable: number }>()).values()];
  const coverageMode = connection.configuration.coverage_mode ?? "automatic";
  return <section className="panel connection-detail">
    <div className="connection-detail-head"><div><span>AMAZON WEB SERVICES</span><h3>{connection.display_name}</h3><code>{awsCredential?.role_arn}</code></div><ConnectionHealth state={connection.health_state} /></div>
    <div className="setup-progress">
      <div className="complete"><span><Check /></span><div><strong>1. Connection plan created</strong><small>Account, scopes, role ARN, and {coverageMode === "automatic" ? "automatic enabled-region coverage" : "the selected-region boundary"} are recorded.</small></div></div>
      <div className={validatedRole ? "complete" : "current"}><span>{validatedRole ? <Check /> : "2"}</span><div><strong>2. Deploy the CloudFormation stack</strong><small>The stack is managed in {connection.configuration.deployment_region ?? "us-east-1"}; its account-wide IAM role does not restrict inventory to that Region. AWS lets you inspect the exact template and permissions before creating it.</small><div className="connection-launch-actions"><button className="primary-action" disabled={launching || !connection.setup_capabilities.cloudformation_quick_create} onClick={onLaunch}><ExternalLink />{launching ? "Waiting for AWS deployment…" : "Launch in AWS"}</button><button className="secondary-action" disabled={busy === `download:${connection.id}`} onClick={onDownload}><Download />{busy === `download:${connection.id}` ? "Downloading…" : "Download template"}</button></div>{!connection.setup_capabilities.cloudformation_quick_create && <small className="launch-unavailable">One-click launch requires the Denali onboarding bucket and runtime principal configuration. Manual template download remains available.</small>}{connection.configuration.onboarding?.template_sha256 && connection.configuration.onboarding.published_at && <small className="launch-record">Last launch prepared {formatTime(connection.configuration.onboarding.published_at)} · template {connection.configuration.onboarding.template_sha256.slice(0, 12)}</small>}</div></div>
      <div className={validation ? (connection.health_state === "healthy" ? "complete" : "attention") : "pending"}><span>{connection.health_state === "healthy" ? <Check /> : "3"}</span><div><strong>3. Discover Regions and validate every plane</strong><small>Role assumption and account binding run first. Enabled Regions are observed next; each applicable regional plane then succeeds or fails independently.</small>{connection.lifecycle_state === "active" && <button className="primary-action" disabled={validating} onClick={onValidate}><RefreshCw className={validating ? "spin" : undefined} />{validating ? "Validating across AWS…" : validation ? "Validate again" : "Validate connection"}</button>}{validating && <small className="validation-progress-note">This continues in the background. Large accounts can take a few minutes.</small>}</div></div>
      <div className={collection ? (collection.failed_count === 0 && collection.partial_count === 0 ? "complete" : "attention") : "pending"}><span>{collection?.failed_count === 0 && collection?.partial_count === 0 ? <Check /> : "4"}</span><div><strong>4. Collect AWS deployments for correlation</strong><small>Denali inventories Lambda, ECS task families, EKS clusters, and SageMaker endpoints across the declared Region boundary. It retains exact deployment identifiers and runtime roles without reading code, prompts, responses, or environment values.</small>{connection.lifecycle_state === "active" && collectionScopeSelected && <button className="primary-action" disabled={collecting || validating || !validatedRole} onClick={onCollectAws}><CloudCog className={collecting ? "spin" : undefined} />{collecting ? "Collecting AWS deployments…" : collection ? "Collect deployments again" : "Collect AWS deployments"}</button>}{!collectionScopeSelected && <small className="launch-unavailable">This connection predates the AWS code-to-cloud scope. Create a new plan to grant and validate the four deployment planes.</small>}{collection && <small className="validation-progress-note">{collection.region_count - collection.failed_count - collection.partial_count} complete · {collection.partial_count} partial · {collection.failed_count} failed · finished {formatTime(collection.completed_at)}</small>}</div></div>
    </div>
    <div className="connection-section"><h4>Validation coverage</h4>{validation ? <><div className={`validation-summary ${validation.health_state}`}><strong>{validation.summary}</strong><small>Checked {formatTime(validation.completed_at)} · observed account {validation.account_id_observed ?? "not established"}</small></div>{regionDiscovery && <div className={`region-discovery ${regionDiscovery.state}`}><span>{regionDiscovery.state === "passed" ? <CircleCheck /> : regionDiscovery.state === "failed" ? <CircleAlert /> : <CircleHelp />}</span><div><strong>{coverageMode === "automatic" ? "Automatic enabled-region coverage" : "Selected-region coverage"}</strong><p>{regionDiscovery.detail}</p>{regionDiscovery.discovered_regions && regionDiscovery.discovered_regions.length > 0 && <small>{regionDiscovery.discovered_regions.join(", ")}</small>}{regionDiscovery.excluded_enabled_regions && regionDiscovery.excluded_enabled_regions.length > 0 && <small className="excluded-regions">Outside declared scope: {regionDiscovery.excluded_enabled_regions.join(", ")}</small>}</div></div>}<div className="validation-plane-rollup">{planeSummaries.map((summary) => <div className={summary.failed || summary.unknown ? "attention" : "complete"} key={summary.label}><span>{summary.failed || summary.unknown ? <CircleAlert /> : <CircleCheck />}</span><div><strong>{summary.label}</strong><small>{summary.total} Region checks</small></div><div className="rollup-counts"><b className="passed">{summary.passed} passed</b>{summary.notApplicable > 0 && <b>{summary.notApplicable} not applicable</b>}{summary.failed > 0 && <b className="failed">{summary.failed} failed</b>}{summary.unknown > 0 && <b className="failed">{summary.unknown} unknown</b>}</div></div>)}</div><details className="plane-validation-results"><summary>View all {planeResults.length} raw plane/Region results</summary><div className="validation-grid">{planeResults.map((result) => <div key={`${result.scope}:${result.plane}:${result.region}`} className={result.state}><span>{result.state === "passed" ? <CircleCheck /> : result.state === "failed" ? <CircleAlert /> : <CircleHelp />}</span><div><strong>{result.label}</strong><small>{result.region} · {result.state === "not_applicable" ? "Not applicable" : titleCase(result.plane)}</small><p>{result.detail}</p></div></div>)}</div></details></> : <div className="connection-unknown"><CircleHelp /><span><strong>Not validated</strong><small>No coverage conclusion is available until the stack is deployed and validation runs.</small></span></div>}</div>
    <details className="connection-permissions"><summary>Review {permissions.length} declared permissions</summary><div>{permissions.map((permission) => <code key={permission}>{permission}</code>)}</div><p>The downloaded role also includes bounded read-only permissions for future explicit stack scopes. Those custom stack planes are not configured or claimed here.</p></details>
    <div className="connection-safeguards"><div><strong>Connection lifecycle</strong><span>Disabling prevents further validation. Deleting removes only connection configuration and validation history; collected evidence remains.</span></div>{connection.lifecycle_state === "active" ? <button disabled={busy === `disable:${connection.id}`} onClick={onDisable}><Power /> Disable</button> : <button className="danger-action" disabled={busy === `delete:${connection.id}`} onClick={onDelete}><Trash2 /> Delete configuration</button>}</div>
  </section>;
}

function AzureConnectionDetail({ connection, busy, launch, completionCode, onCompletionCode, onPrepare, onComplete, onCollect, onValidate, onDisable, onDelete }: { connection: Connection; busy: string | null; launch?: AzureSetupLaunch; completionCode: string; onCompletionCode: (value: string) => void; onPrepare: () => void; onComplete: () => void; onCollect: () => void; onValidate: () => void; onDisable: () => void; onDelete: () => void }) {
  const validation = connection.last_validation;
  const subscriptions = connection.configuration.subscriptions ?? [];
  const setupComplete = subscriptions.length > 0;
  const preparing = busy === `launch:${connection.id}`;
  const completing = busy === `complete:${connection.id}`;
  const validating = connection.validation_state === "running" || busy === `validate:${connection.id}` || completing;
  const collecting = connection.deployment_collection_state === "running" || busy === `collect-azure:${connection.id}`;
  const collection = connection.last_deployment_collection && "subscription_count" in connection.last_deployment_collection ? connection.last_deployment_collection : null;
  const collectionScopeSelected = connection.declared_scopes.includes("azure.code_to_cloud");
  const credential = connection.credential_reference.type === "azure_multitenant_app" ? connection.credential_reference : null;
  const permissions = [...new Set(connection.coverage_plan.flatMap((item) => item.permissions))].sort();
  return <section className="panel connection-detail">
    <div className="connection-detail-head"><div><span>MICROSOFT AZURE</span><h3>{connection.display_name}</h3><code>Tenant {connection.configuration.tenant_id}</code></div><ConnectionHealth state={connection.health_state} /></div>
    <div className="setup-progress">
      <div className="complete"><span><Check /></span><div><strong>1. Connection plan created</strong><small>Tenant, application ID, scopes, and subscription-selection boundary are recorded. Entra directory access is not included.</small></div></div>
      <div className={setupComplete ? "complete" : "current"}><span>{setupComplete ? <Check /> : "2"}</span><div><strong>2. Add Denali to the tenant and select subscriptions</strong><small>Microsoft Entra first creates a tenant-local enterprise application—the identity Azure can assign a role to. This grants no subscription or Microsoft Graph access. Cloud Shell then enumerates enabled subscriptions and assigns Reader only to those you select; every resource location inside them remains in scope.</small>{!launch && <button className="primary-action" disabled={preparing || !connection.setup_capabilities.azure_cloud_shell} onClick={onPrepare}><ExternalLink />{preparing ? "Preparing Azure setup…" : setupComplete ? "Prepare Azure setup again" : "Prepare Azure setup"}</button>}{launch && <div className="azure-setup-actions"><div className="connection-launch-actions"><a className="primary-action" href={launch.consent_url} target="_blank" rel="noreferrer"><ExternalLink />1. Add Denali to tenant</a><a className="secondary-action" href={launch.cloud_shell_url} target="_blank" rel="noreferrer"><ExternalLink />2. Open Cloud Shell</a><a className="secondary-action" href={launch.script_url} download><Download />Download script</a></div><small className="azure-consent-guidance">Required only once per Entra tenant. This Microsoft-hosted step opens in a new tab and creates—or confirms an existing—Denali enterprise application. It requests no Graph permissions and grants no subscription access; Cloud Shell grants Reader separately.</small><label className="azure-command"><span>3. Run in Cloud Shell</span><textarea readOnly value={launch.setup_command} /><button type="button" onClick={() => void navigator.clipboard.writeText(launch.setup_command)}>Copy command</button><small>The command downloads the same reviewable script shown by Download script. Its URL expires at {formatTime(launch.expires_at)}.</small></label><label className="azure-completion"><span>4. Paste the completion code printed by the script</span><textarea value={completionCode} onChange={(event) => onCompletionCode(event.target.value)} placeholder="DENALI_SETUP_COMPLETE=…" /><button className="primary-action" type="button" disabled={completing || !completionCode.trim()} onClick={onComplete}>{completing ? "Waiting for Azure access propagation…" : "Complete setup and validate"}</button><small>New Azure role assignments can take several minutes to propagate. Denali retries the declared checks before recording a partial result.</small></label></div>}{!connection.setup_capabilities.azure_cloud_shell && <small className="launch-unavailable">Cloud Shell setup requires Denali’s multi-tenant Azure application and private onboarding-script publisher.</small>}{setupComplete && <div className="azure-subscriptions"><strong>{subscriptions.length} selected subscription{subscriptions.length === 1 ? "" : "s"}</strong>{subscriptions.map((subscription) => <code key={subscription.id}>{subscription.name} · {subscription.id}</code>)}</div>}</div></div>
      <div className={validation ? (connection.health_state === "healthy" ? "complete" : "attention") : "pending"}><span>{connection.health_state === "healthy" ? <Check /> : "3"}</span><div><strong>3. Validate every selected subscription</strong><small>Denali binds the customer tenant and each exact subscription first, then validates every declared subscription-wide plane independently.</small>{connection.lifecycle_state === "active" && setupComplete && <button className="primary-action" disabled={validating} onClick={onValidate}><RefreshCw className={validating ? "spin" : undefined} />{validating ? "Validating Azure…" : validation ? "Validate again" : "Validate connection"}</button>}</div></div>
      <div className={collection ? (collection.state === "complete" ? "complete" : "attention") : "pending"}><span>{collection?.state === "complete" ? <Check /> : "4"}</span><div><strong>4. Collect deployment identities</strong><small>Read Container Apps and Function Apps through Azure Resource Graph, retaining exact subscription, resource group, location, revision, image, and managed-identity evidence without storing app-setting values.</small>{connection.lifecycle_state === "active" && setupComplete && <button className="primary-action" disabled={!collectionScopeSelected || collecting || validating} onClick={onCollect}><CloudCog className={collecting ? "spin" : undefined} />{collecting ? "Collecting deployments…" : collection ? "Collect deployments again" : "Collect deployments"}</button>}{!collectionScopeSelected && <small className="launch-unavailable">This connection predates the Azure code-to-cloud scope. Create a new Azure connection plan to adopt and validate it explicitly.</small>}{collection && <small className="validation-progress-note">{collection.subscription_count - collection.failed_count - collection.partial_count} complete · {collection.partial_count} partial · {collection.failed_count} failed · finished {formatTime(collection.completed_at)}</small>}</div></div>
    </div>
    <div className="connection-section"><h4>Validation coverage</h4>{validation ? <><div className={`validation-summary ${validation.health_state}`}><strong>{validation.summary}</strong><small>Checked {formatTime(validation.completed_at)} · observed subscriptions {validation.account_id_observed ?? "not established"}</small></div><div className="validation-grid">{validation.results.map((result) => <div key={`${result.subscription_id}:${result.plane}`} className={result.state}><span>{result.state === "passed" ? <CircleCheck /> : result.state === "failed" ? <CircleAlert /> : <CircleHelp />}</span><div><strong>{result.label}</strong><small>{result.subscription_name ?? result.subscription_id} · all resource locations</small><p>{result.detail}</p></div></div>)}</div></> : <div className="connection-unknown"><CircleHelp /><span><strong>Not validated</strong><small>Authorize the application, select subscriptions, and paste the Cloud Shell completion code first.</small></span></div>}</div>
    <details className="connection-permissions"><summary>Review {permissions.length || 2} declared Azure permissions</summary><div>{(permissions.length ? permissions : ["Microsoft.Resources/subscriptions/read", "Microsoft.Authorization/roleAssignments/read"]).map((permission) => <code key={permission}>{permission}</code>)}</div><p>The customer grants Azure Reader only at selected subscription scopes. This does not grant Microsoft Graph/Entra directory reads, data-plane access, secret access, prompt access, response access, or remediation.</p></details>
    <div className="connection-safeguards"><div><strong>Connection lifecycle</strong><span>Disabling prevents further validation. Deleting removes only connection configuration and validation history; Azure role assignments must be removed in Azure and collected evidence remains.</span>{credential?.service_principal_id && <code>Service principal {credential.service_principal_id}</code>}</div>{connection.lifecycle_state === "active" ? <button disabled={busy === `disable:${connection.id}`} onClick={onDisable}><Power /> Disable</button> : <button className="danger-action" disabled={busy === `delete:${connection.id}`} onClick={onDelete}><Trash2 /> Delete configuration</button>}</div>
  </section>;
}

function GcpConnectionDetail({ connection, busy, launch, completionCode, onCompletionCode, onPrepare, onComplete, onCollect, onValidate, onDisable, onDelete }: { connection: Connection; busy: string | null; launch?: GcpSetupLaunch; completionCode: string; onCompletionCode: (value: string) => void; onPrepare: () => void; onComplete: () => void; onCollect: () => void; onValidate: () => void; onDisable: () => void; onDelete: () => void }) {
  const validation = connection.last_validation;
  const projects = connection.configuration.projects ?? [];
  const setupComplete = projects.length > 0;
  const preparing = busy === `launch:${connection.id}`;
  const completing = busy === `complete:${connection.id}`;
  const validating = connection.validation_state === "running" || busy === `validate:${connection.id}` || completing;
  const collecting = connection.deployment_collection_state === "running" || busy === `collect-gcp:${connection.id}`;
  const collection = connection.last_deployment_collection && "project_count" in connection.last_deployment_collection ? connection.last_deployment_collection : null;
  const credential = connection.credential_reference.type === "gcp_service_account" ? connection.credential_reference : null;
  const permissions = [...new Set(connection.coverage_plan.flatMap((item) => item.permissions))].sort();
  return <section className="panel connection-detail">
    <div className="connection-detail-head"><div><span>GOOGLE CLOUD</span><h3>{connection.display_name}</h3><code>{credential?.principal_email}</code></div><ConnectionHealth state={connection.health_state} /></div>
    <div className="setup-progress">
      <div className="complete"><span><Check /></span><div><strong>1. Connection plan created</strong><small>A unique keyless Denali service account, declared scopes, and customer-controlled project-selection boundary are recorded. No customer key or user token is requested.</small></div></div>
      <div className={setupComplete ? "complete" : "current"}><span>{setupComplete ? <Check /> : "2"}</span><div><strong>2. Select projects and grant bounded read access</strong><small>Google Cloud Shell enumerates active projects visible to your signed-in identity. Cloud Asset Viewer and Logs Viewer are granted only to projects you select; every resource location inside them remains in scope.</small>{!launch && <button className="primary-action" disabled={preparing || !connection.setup_capabilities.gcp_cloud_shell} onClick={onPrepare}><ExternalLink />{preparing ? "Preparing Google Cloud setup…" : setupComplete ? "Prepare Google Cloud setup again" : "Prepare Google Cloud setup"}</button>}{launch && <div className="azure-setup-actions"><div className="connection-launch-actions"><a className="primary-action" href={launch.cloud_shell_url} target="_blank" rel="noreferrer"><ExternalLink />1. Open Cloud Shell</a><a className="secondary-action" href={launch.script_url} download><Download />Download script</a></div><small className="azure-consent-guidance">Cloud Shell uses your existing Google session only to enumerate projects and update IAM policies. Denali never receives that session or a customer service-account key.</small><label className="azure-command"><span>2. Run in Cloud Shell</span><textarea readOnly value={launch.setup_command} /><button type="button" onClick={() => void navigator.clipboard.writeText(launch.setup_command)}>Copy command</button><small>The command downloads the same reviewable script shown by Download script. Its URL expires at {formatTime(launch.expires_at)}.</small></label><label className="azure-completion"><span>3. Paste the completion code printed by the script</span><textarea value={completionCode} onChange={(event) => onCompletionCode(event.target.value)} placeholder="DENALI_GCP_SETUP_COMPLETE=…" /><button className="primary-action" type="button" disabled={completing || !completionCode.trim()} onClick={onComplete}>{completing ? "Waiting for Google Cloud IAM propagation…" : "Complete setup and validate"}</button><small>New Google Cloud IAM bindings can take several minutes to propagate. Denali retries the declared checks before recording a partial result.</small></label></div>}{!connection.setup_capabilities.gcp_cloud_shell && <small className="launch-unavailable">Cloud Shell setup requires Denali’s Google Cloud service account and private onboarding-script publisher.</small>}{setupComplete && <div className="azure-subscriptions"><strong>{projects.length} selected project{projects.length === 1 ? "" : "s"}</strong>{projects.map((project) => <code key={project.id}>{project.name} · {project.id} · {project.number}</code>)}</div>}</div></div>
      <div className={validation ? (connection.health_state === "healthy" ? "complete" : "attention") : "pending"}><span>{connection.health_state === "healthy" ? <Check /> : "3"}</span><div><strong>3. Validate every selected project</strong><small>Denali binds each exact project ID and immutable project number first, then validates every declared project-wide plane independently.</small>{connection.lifecycle_state === "active" && setupComplete && <button className="primary-action" disabled={validating} onClick={onValidate}><RefreshCw className={validating ? "spin" : undefined} />{validating ? "Validating Google Cloud…" : validation ? "Validate again" : "Validate connection"}</button>}</div></div>
      <div className={collection ? (collection.state === "complete" ? "complete" : "attention") : "pending"}><span>{collection?.state === "complete" ? <Check /> : "4"}</span><div><strong>4. Collect deployment identities</strong><small>Read Cloud Run and Cloud Run functions through Cloud Asset Inventory, retain exact project/location/resource and revision evidence, and classify AI workloads without storing environment values.</small>{connection.lifecycle_state === "active" && setupComplete && <button className="primary-action" disabled={collecting || validating} onClick={onCollect}><CloudCog className={collecting ? "spin" : undefined} />{collecting ? "Collecting deployments…" : collection ? "Collect deployments again" : "Collect deployments"}</button>}{collection && <small className="validation-progress-note">{collection.project_count - collection.failed_count - collection.partial_count} complete · {collection.partial_count} partial · {collection.failed_count} failed · finished {formatTime(collection.completed_at)}</small>}</div></div>
    </div>
    <div className="connection-section"><h4>Validation coverage</h4>{validation ? <><div className={`validation-summary ${validation.health_state}`}><strong>{validation.summary}</strong><small>Checked {formatTime(validation.completed_at)} · observed projects {validation.account_id_observed ?? "not established"}</small></div><div className="validation-grid">{validation.results.map((result) => <div key={`${result.project_id}:${result.plane}`} className={result.state}><span>{result.state === "passed" ? <CircleCheck /> : result.state === "failed" ? <CircleAlert /> : <CircleHelp />}</span><div><strong>{result.label}</strong><small>{result.project_name ?? result.project_id} · all resource locations</small><p>{result.detail}</p></div></div>)}</div></> : <div className="connection-unknown"><CircleHelp /><span><strong>Not validated</strong><small>Select projects in Cloud Shell and paste its completion code first.</small></span></div>}</div>
    <details className="connection-permissions"><summary>Review {permissions.length || 2} declared Google Cloud permissions</summary><div>{(permissions.length ? permissions : ["cloudasset.assets.searchAllResources", "logging.logEntries.list"]).map((permission) => <code key={permission}>{permission}</code>)}</div><p>The customer grants Cloud Asset Viewer and Logs Viewer only on selected projects. This does not grant writes, service-account key access, prompt or response contents, or remediation.</p></details>
    <div className="connection-safeguards"><div><strong>Connection lifecycle</strong><span>Disabling prevents further validation. Deleting removes only connection configuration and validation history; customer-project IAM bindings and the Denali-owned service account require separate cleanup, while collected evidence remains.</span>{credential?.principal_unique_id && <code>Immutable service-account ID {credential.principal_unique_id}</code>}</div>{connection.lifecycle_state === "active" ? <button disabled={busy === `disable:${connection.id}`} onClick={onDisable}><Power /> Disable</button> : <button className="danger-action" disabled={busy === `delete:${connection.id}`} onClick={onDelete}><Trash2 /> Delete configuration</button>}</div>
  </section>;
}

function GitHubConnectionDetail({ connection, busy, navigation, onPrepare, onCollect, onValidate, onDisable, onDelete }: { connection: Connection; busy: string | null; navigation: FilterNavigation; onPrepare: () => void; onCollect: () => void; onValidate: () => void; onDisable: () => void; onDelete: () => void }) {
  const validation = connection.last_validation;
  const repositories = connection.configuration.repositories ?? [];
  const setupComplete = repositories.length > 0;
  const preparing = busy === `launch:${connection.id}`;
  const validating = connection.validation_state === "running" || busy === `validate:${connection.id}`;
  const credential = connection.credential_reference.type === "github_app_installation" ? connection.credential_reference : null;
  const permissions = [...new Set(connection.coverage_plan.flatMap((item) => item.permissions))].sort();
  const validationFilter = (["attention", "all", "passed"] as const).includes(navigation.values.validation as "attention" | "all" | "passed")
    ? navigation.values.validation as "attention" | "all" | "passed"
    : "attention";
  const recordedResults = validation?.results ?? [];
  const recordedByRepository = recordedResults.reduce((grouped, result) => {
    if (result.repository_id === undefined) return grouped;
    grouped.set(result.repository_id, [...(grouped.get(result.repository_id) ?? []), result]);
    return grouped;
  }, new Map<number, ConnectionValidationResult[]>());
  const repositoryIds = new Set(repositories.map((repository) => repository.id));
  const repositoryGroups = repositories.map((repository) => {
    const recorded = recordedByRepository.get(repository.id) ?? [];
    const declared = connection.coverage_plan.filter((item) => item.repository_id === repository.id);
    const missing = declared
      .filter((item) => !recorded.some((result) => result.plane === item.plane))
      .map<ConnectionValidationResult>((item) => ({
        scope: item.scope,
        plane: item.plane,
        label: item.label,
        region: item.region,
        state: "unknown",
        detail: "No validation result was recorded for this declared plane.",
        repository_id: repository.id,
        repository_full_name: repository.full_name,
      }));
    const results = [...recorded, ...missing].sort((left, right) => validationStateRank(left.state) - validationStateRank(right.state) || left.label.localeCompare(right.label));
    const attention = results.filter((result) => result.state === "failed" || result.state === "unknown").length;
    const passed = results.filter((result) => result.state === "passed").length;
    return { repository, results, attention, passed };
  }).sort((left, right) => Number(right.attention > 0) - Number(left.attention > 0) || left.repository.full_name.localeCompare(right.repository.full_name));
  const unboundResults = recordedResults.filter((result) => result.repository_id === undefined || !repositoryIds.has(result.repository_id));
  const attentionRepositories = repositoryGroups.filter((group) => group.attention > 0).length;
  const passingRepositories = repositoryGroups.filter((group) => group.results.length > 0 && group.attention === 0).length;
  const totalPassed = repositoryGroups.reduce((total, group) => total + group.passed, 0);
  const totalAttention = repositoryGroups.reduce((total, group) => total + group.attention, 0) + unboundResults.length;
  const effectiveFilter = validationFilter === "attention" && attentionRepositories === 0 && unboundResults.length === 0 ? "all" : validationFilter;
  const visibleGroups = repositoryGroups.filter((group) => effectiveFilter === "all" || (effectiveFilter === "attention" ? group.attention > 0 : group.attention === 0));
  const collecting = connection.source_collection_state === "running" || busy === `collect:${connection.id}`;
  const collection = connection.last_source_collection;
  return <section className="panel connection-detail">
    <div className="connection-detail-head"><div><span>GITHUB</span><h3>{connection.display_name}</h3><code>{connection.configuration.account_login ? `${connection.configuration.account_type ?? "Account"} ${connection.configuration.account_login}` : credential ? `GitHub App ${credential.app_slug}` : "GitHub App"}</code></div><ConnectionHealth state={connection.health_state} /></div>
    <div className="setup-progress">
      <div className="complete"><span><Check /></span><div><strong>1. Connection plan created</strong><small>Denali’s GitHub App, declared read planes, and an initially empty repository boundary are recorded. No personal access token is requested or stored.</small></div></div>
      <div className={setupComplete ? "complete" : "current"}><span>{setupComplete ? <Check /> : "2"}</span><div><strong>2. Install the App and select repositories</strong><small>GitHub shows the App’s exact read permissions and lets you choose repositories. After installation, Denali briefly verifies that the signed-in GitHub user can access that exact installation, records immutable repository IDs, and immediately discards the user token.</small><button className="primary-action" disabled={preparing || !connection.setup_capabilities.github_app} onClick={onPrepare}><ExternalLink />{preparing ? "Opening GitHub…" : setupComplete ? "Reconfigure GitHub App" : "Install / configure GitHub App"}</button>{!connection.setup_capabilities.github_app && <small className="launch-unavailable">GitHub onboarding requires Denali’s configured GitHub App and private signing key.</small>}{setupComplete && <div className="azure-subscriptions"><strong>{repositories.length} exact repositor{repositories.length === 1 ? "y" : "ies"}</strong>{repositories.map((repository) => <code key={repository.id}>{repository.full_name} · ID {repository.id}{repository.private ? " · private" : " · public"}</code>)}{connection.configuration.installation_repository_selection === "all" && <small>GitHub’s installation is set to all repositories, but Denali’s stored coverage remains this exact list. Newly created repositories are not claimed until you reconfigure and verify again.</small>}</div>}</div></div>
      <div className={validation ? (connection.health_state === "healthy" ? "complete" : "attention") : "pending"}><span>{connection.health_state === "healthy" ? <Check /> : "3"}</span><div><strong>3. Validate every exact repository</strong><small>Denali mints a separate short-lived installation token for one recorded repository at a time, rebinds its immutable identity, and tests each declared read plane independently.</small>{connection.lifecycle_state === "active" && setupComplete && <button className="primary-action" disabled={validating} onClick={onValidate}><RefreshCw className={validating ? "spin" : undefined} />{validating ? "Validating GitHub…" : validation ? "Validate again" : "Validate connection"}</button>}{validating && <small className="validation-progress-note">Validation continues in the background. This page refreshes automatically when every repository is complete.</small>}</div></div>
      <div className={collection ? (collection.failed_count === 0 && collection.partial_count === 0 ? "complete" : "attention") : "pending"}><span>{collection?.failed_count === 0 && collection?.partial_count === 0 ? <Check /> : "4"}</span><div><strong>4. Collect source and correlate</strong><small>Denali resolves each default branch to an immutable commit, downloads only bounded analysis inputs with a repository-scoped token, and joins literal deployment identifiers to independently observed cloud workloads.</small>{connection.lifecycle_state === "active" && setupComplete && <button className="primary-action" disabled={collecting || validating} onClick={onCollect}><GitBranch className={collecting ? "spin" : undefined} />{collecting ? "Collecting and correlating…" : collection ? "Collect and correlate again" : "Collect source & correlate"}</button>}{collection && <small className="validation-progress-note">{collection.repository_count - collection.failed_count - collection.partial_count} complete · {collection.partial_count} partial · {collection.failed_count} failed · finished {formatTime(collection.completed_at)}</small>}</div></div>
    </div>
    <div className="connection-section"><h4>Validation coverage</h4>{validation ? <><div className={`validation-summary ${validation.health_state}`}><strong>{validation.summary}</strong><small>Checked {formatTime(validation.completed_at)} · observed GitHub account ID {validation.account_id_observed ?? "not established"}</small></div><div className="github-validation-overview"><div><small>Exact repositories</small><strong>{repositories.length}</strong><span>{attentionRepositories > 0 ? `${attentionRepositories} need attention` : unboundResults.length > 0 ? `${unboundResults.length} unbound result${unboundResults.length === 1 ? "" : "s"}` : "All repository boundaries checked"}</span></div><div><small>Independent plane checks</small><strong>{repositoryGroups.reduce((total, group) => total + group.results.length, 0)}</strong><span>Metadata · Contents · Actions</span></div><div className="passed"><small>Passed</small><strong>{totalPassed}</strong><span>Successful read checks</span></div><div className={totalAttention > 0 ? "attention" : "passed"}><small>Failed or unknown</small><strong>{totalAttention}</strong><span>{totalAttention > 0 ? "Expanded below" : "No unresolved checks"}</span></div></div><div className="github-validation-toolbar"><div><strong>Repository results</strong><small>Failures and unknowns are listed first. Passing repositories stay compact until expanded.</small></div><div role="group" aria-label="Filter repository validation results"><button type="button" className={effectiveFilter === "attention" ? "active" : ""} disabled={attentionRepositories === 0 && unboundResults.length === 0} onClick={() => navigation.set("validation", "attention", "attention")}>Needs attention <span>{attentionRepositories + (unboundResults.length > 0 ? 1 : 0)}</span></button><button type="button" className={effectiveFilter === "all" ? "active" : ""} onClick={() => navigation.set("validation", "all", "attention")}>All <span>{repositoryGroups.length + (unboundResults.length > 0 ? 1 : 0)}</span></button><button type="button" className={effectiveFilter === "passed" ? "active" : ""} disabled={passingRepositories === 0} onClick={() => navigation.set("validation", "passed", "attention")}>Passing <span>{passingRepositories}</span></button></div></div>{effectiveFilter !== "passed" && unboundResults.length > 0 && <details className="github-repository-validation attention" open><summary><span className="github-repository-state"><CircleAlert /></span><span><strong>Unbound validation results</strong><small>These results do not match a repository in the recorded exact boundary.</small></span><span className="github-plane-statuses" /><span className="github-repository-counts"><b>{unboundResults.length} unknown</b></span></summary><div className="github-plane-results">{unboundResults.map((result, index) => <GitHubValidationResult key={`${result.repository_id ?? "unbound"}:${result.plane}:${index}`} result={result} />)}</div></details>}<div className="github-repository-validations">{visibleGroups.map((group) => <details className={`github-repository-validation ${group.attention > 0 ? "attention" : "passed"}`} key={group.repository.id} open={group.attention > 0}><summary><span className="github-repository-state">{group.attention > 0 ? <CircleAlert /> : <CircleCheck />}</span><span><strong>{group.repository.full_name}</strong><small><code>Repository ID {group.repository.id}</code><code>Node ID {group.repository.node_id}</code></small></span><span className="github-plane-statuses">{group.results.map((result) => <i className={result.state} key={result.plane} title={`${result.label}: ${titleCase(result.state)}`}>{result.state === "passed" ? <CircleCheck /> : result.state === "failed" ? <CircleAlert /> : <CircleHelp />}<em>{result.label.replace("Repository ", "")}</em></i>)}</span><span className="github-repository-counts"><b className={group.attention > 0 ? "attention" : "passed"}>{group.attention > 0 ? `${group.attention} need attention` : `${group.passed} passed`}</b><small>{group.attention > 0 ? "Details expanded" : "Details collapsed"}</small></span></summary><div className="github-plane-results">{group.results.map((result) => <GitHubValidationResult key={`${group.repository.id}:${result.plane}`} result={result} />)}</div></details>)}</div>{visibleGroups.length === 0 && <div className="connection-unknown"><CircleHelp /><span><strong>No repositories match this filter</strong><small>Choose another result filter to inspect the recorded repository boundary.</small></span></div>}</> : <div className="connection-unknown"><CircleHelp /><span><strong>Not validated</strong><small>Install the GitHub App and finish repository selection first.</small></span></div>}</div>
    <details className="connection-permissions"><summary>Review {permissions.length || 3} declared GitHub permissions</summary><div>{(permissions.length ? permissions : ["metadata:read", "contents:read", "actions:read"]).map((permission) => <code key={permission}>{permission}</code>)}</div><p>This slice cannot write source, dispatch workflows, read Actions secrets, administer repositories, receive webhooks, or access repositories outside the recorded immutable IDs. Branch-protection posture is not claimed.</p></details>
    <div className="connection-safeguards"><div><strong>Connection lifecycle</strong><span>Disabling prevents further validation. Deleting removes Denali’s connection configuration and validation history only; uninstall the GitHub App separately in GitHub. Previously collected evidence remains.</span>{credential?.installation_id && <code>Installation ID {credential.installation_id}</code>}{connection.configuration.installer && <code>Verified installer {connection.configuration.installer.login} · user ID {connection.configuration.installer.id}</code>}</div>{connection.lifecycle_state === "active" ? <button disabled={busy === `disable:${connection.id}`} onClick={onDisable}><Power /> Disable</button> : <button className="danger-action" disabled={busy === `delete:${connection.id}`} onClick={onDelete}><Trash2 /> Delete configuration</button>}</div>
  </section>;
}

function validationStateRank(state: ConnectionValidationResult["state"]) {
  return state === "failed" ? 0 : state === "unknown" ? 1 : state === "not_applicable" ? 2 : 3;
}

function GitHubValidationResult({ result }: { result: ConnectionValidationResult }) {
  return <div className={result.state}><span>{result.state === "passed" ? <CircleCheck /> : result.state === "failed" ? <CircleAlert /> : <CircleHelp />}</span><div><strong>{result.label}</strong><small>{titleCase(result.state)} · {titleCase(result.plane)}</small><p>{result.detail}</p></div></div>;
}

function Sources({ coverage }: { coverage: Coverage[] }) {
  const grouped = coverage.reduce<Map<string, Coverage[]>>((result, item) => {
    const key = `${item.connector_id}:${item.connection_id}`;
    result.set(key, [...(result.get(key) ?? []), item]);
    return result;
  }, new Map());
  return <div className="page-stack"><section className="page-intro"><div><span className="eyebrow">COVERAGE BEFORE COUNTS</span><h2>Know exactly what each source could see.</h2><p>Denali keeps partial, failed, unsupported, and unknown coverage visible—never disguised as zero risk.</p></div></section><section className="source-grid">{[...grouped.entries()].map(([key, items]) => {
    const healthy = items.every((item) => item.state === "complete");
    const scopes = [...new Set(items.map((item) => item.scope))];
    const latestCollection = items.reduce((latest, item) => item.collected_at > latest ? item.collected_at : latest, items[0].collected_at);
    const fixtureSource = items[0].connector_id === "denali.demo" || items[0].connector_id.startsWith("denali.demo.");
    const HealthIcon = healthy ? CircleCheck : CircleAlert;
    return <div className="panel source-card" key={key}>
      <div className="source-card-head"><span className="connector-icon"><Waypoints /></span><div><span>CONNECTOR</span><h3>{items[0].connector_id}</h3><p>{items[0].connection_id}</p></div><span className={`source-health ${healthy ? "healthy" : "attention"}`}><HealthIcon /> {healthy ? "Healthy" : "Needs attention"}</span></div>
      <div className="source-meta"><span><Clock3 />Last collection <strong>{formatTime(latestCollection)}</strong></span><span><Fingerprint />{scopes.length === 1 ? "Scope" : "Scopes"} <strong>{scopes.length === 1 ? scopes[0] : `${scopes.length} declared scopes`}</strong></span></div>
      <div className="source-planes"><h4>Declared collection planes</h4>{items.map((item) => <CoverageRow key={`${item.plane}-${item.scope}`} item={item} />)}</div>
      {fixtureSource && <div className="fixture-banner"><CircleHelp /><span><strong>Transparent fixture source</strong>This connector exists only to exercise the local product experience.</span></div>}
    </div>;
  })}</section></div>;
}

function ResourceDrawer({
  assetId,
  tab,
  onTab,
  onClose,
  onOpenAsset,
  onOpenActivity,
  onUpdated,
  canWrite,
}: {
  assetId: string;
  tab: DetailTab;
  onTab: (tab: string) => void;
  onClose: () => void;
  onOpenAsset: (id: string) => void;
  onOpenActivity: (id: string) => void;
  onUpdated: () => void;
  canWrite: boolean;
}) {
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [assetActivities, setAssetActivities] = useState<RuntimeActivity[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDetail(null); setAssetActivities([]); setError(null);
    Promise.all([api.asset(assetId), api.activityForAsset(assetId)])
      .then(([asset, activity]) => {
        setDetail(asset);
        setAssetActivities(activity.items);
      })
      .catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load resource"));
  }, [assetId]);

  async function updateGovernance(status: Asset["governance_status"]) {
    if (!detail || saving) return;
    setSaving(true);
    try {
      await api.governance(detail.id, { status, owner: detail.owner, notes: detail.notes });
      setDetail({ ...detail, governance_status: status });
      void onUpdated();
    } finally { setSaving(false); }
  }

  const itemMeta = detail ? meta(detail.kind) : FALLBACK_META;
  const Icon = itemMeta.icon;
  return <div className="drawer-layer"><button className="drawer-scrim" onClick={onClose} aria-label="Close resource detail" /><aside className="resource-drawer" aria-label="Resource detail">
    {!detail && !error ? <LoadingState compact /> : error ? <ErrorState message={error} /> : detail && <>
      <div className="drawer-header"><button className="drawer-close" onClick={onClose}><X /></button><span className={`asset-icon large ${itemMeta.color}`}><Icon /></span><div><span>{itemMeta.label}</span><h2>{detail.assertions[0]?.display_name ?? shortKey(detail.natural_key)}</h2><p>{detail.natural_key}</p></div><span className={`lifecycle-badge ${detail.lifecycle_state}`}><span />{titleCase(detail.lifecycle_state)}</span></div>
      {canWrite ? <div className="drawer-actions"><span>Governance</span>{(["approved", "unreviewed", "unwanted"] as const).map((status) => <button key={status} disabled={saving} className={detail.governance_status === status ? "active" : ""} onClick={() => void updateGovernance(status)}>{status === "approved" ? <CircleCheck /> : status === "unwanted" ? <CircleAlert /> : <CircleHelp />}{titleCase(status)}</button>)}</div> : <div className="drawer-read-only"><ShieldCheck /> Governance is read-only for organization members.</div>}
      <div className="drawer-tabs">{(["overview", "relationships", "evidence"] as const).map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => onTab(item)}>{titleCase(item)}{item === "relationships" && <small>{detail.relationships.length}</small>}{item === "evidence" && <small>{detail.assertions.length}</small>}</button>)}</div>
      <div className="drawer-content">
        {tab === "overview" ? <OverviewTab detail={detail} activities={assetActivities} onOpenAsset={onOpenAsset} onOpenActivity={onOpenActivity} /> : tab === "relationships" ? <RelationshipsTab detail={detail} onOpenAsset={onOpenAsset} /> : <EvidenceTab detail={detail} />}
      </div>
    </>}
  </aside></div>;
}

function OverviewTab({
  detail,
  activities,
  onOpenAsset,
  onOpenActivity,
}: {
  detail: AssetDetail;
  activities: RuntimeActivity[];
  onOpenAsset: (id: string) => void;
  onOpenActivity: (id: string) => void;
}) {
  const assertion = detail.assertions[0];
  return <div className="detail-stack"><div className="insight-strip"><Sparkles /><div><span>DENALI INSIGHT</span><strong>This resource is externally verified and linked to {detail.relationships.length} parts of the AI system.</strong><p>Security conclusions remain separate from this inventory assertion.</p></div></div><DetailSection title="Properties"><div className="property-grid"><Property label="Resource type" value={meta(detail.kind).label} /><Property label="Lifecycle" value={titleCase(detail.lifecycle_state)} /><Property label="Assertion" value={titleCase(assertion.assertion_type)} /><Property label="Confidence" value={`${Math.round(assertion.confidence * 100)}%`} /><Property label="First seen" value={formatTime(detail.first_seen_at)} /><Property label="Last changed" value={formatTime(detail.last_changed_at)} /><Property label="Connector" value={assertion.connector_id} /><Property label="Collection scope" value={assertion.scope_key} /></div></DetailSection>{Object.keys(assertion.attributes).length > 0 && <DetailSection title="Normalized attributes"><div className="attribute-list">{Object.entries(assertion.attributes).map(([key, value]) => <div key={key}><span>{titleCase(key)}</span><AttributeValue value={value} /></div>)}</div></DetailSection>}{detail.kind === "ai_application" && <ApplicationIdentityContext detail={detail} activities={activities} onOpenActivity={onOpenActivity} />}<DetailSection title="Connected system"><div className="relationship-preview">{detail.relationships.slice(0, 5).map((relation) => <RelationshipRow key={relation.id} relation={relation} currentId={detail.id} onOpenAsset={onOpenAsset} />)}</div></DetailSection></div>;
}

function AttributeValue({ value }: { value: unknown }) {
  if (value === null || value === undefined || value === "") {
    return <strong className="attribute-empty">Not provided</strong>;
  }
  if (typeof value === "boolean") return <strong>{value ? "Yes" : "No"}</strong>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <strong className="attribute-empty">None observed</strong>;
    return <strong className="attribute-values">{value.map((item, index) => <span className="attribute-chip" key={`${String(item)}-${index}`}>{String(item)}</span>)}</strong>;
  }
  if (typeof value === "object") return <strong>{JSON.stringify(value)}</strong>;
  return <strong>{String(value)}</strong>;
}

type ObservedActor = {
  key: string;
  name: string;
  latest: RuntimeActivity;
  count: number;
};

function observedActors(activities: RuntimeActivity[]): ObservedActor[] {
  const actors = new Map<string, ObservedActor>();
  for (const activity of activities) {
    const key = activity.actor_uid ?? activity.actor_name ?? `unknown:${activity.id}`;
    const existing = actors.get(key);
    if (!existing) {
      actors.set(key, {
        key,
        name: activity.actor_name ?? shortKey(activity.actor_uid ?? "Unknown actor"),
        latest: activity,
        count: 1,
      });
      continue;
    }
    existing.count += 1;
    if (activity.occurred_at > existing.latest.occurred_at) existing.latest = activity;
  }
  return [...actors.values()].sort((left, right) => right.latest.occurred_at.localeCompare(left.latest.occurred_at));
}

function ApplicationIdentityContext({
  detail,
  activities,
  onOpenActivity,
}: {
  detail: AssetDetail;
  activities: RuntimeActivity[];
  onOpenActivity: (id: string) => void;
}) {
  const assertion = detail.assertions[0];
  const signIns = observedActors(activities.filter((item) => item.category === "ai_app_sign_in"));
  const changes = observedActors(activities.filter((item) => item.category === "admin_change"));
  const delegatedGrantCount = Number(assertion.attributes.delegated_grant_count ?? 0);
  const consentTypes = Array.isArray(assertion.attributes.delegated_consent_types)
    ? assertion.attributes.delegated_consent_types.map(String)
    : [];
  const tenantWideConsent = consentTypes.includes("AllPrincipals");

  return <DetailSection title="Observed users and changes">
    <div className="identity-context-intro"><Fingerprint /><div><strong>Identity evidence, with its limits</strong><p>Sign-ins prove observed use, not ownership. Directory audit records identify a configuration actor only when Microsoft retained a matching event.</p></div></div>
    <div className="observed-actor-groups">
      <ObservedActorGroup title="People who signed in" empty="No matching sign-ins were observed in the collected window." actors={signIns} onOpenActivity={onOpenActivity} />
      <ObservedActorGroup title="Consent & configuration actors" empty="No matching directory-audit actor was observed in the collected window." actors={changes} onOpenActivity={onOpenActivity} />
    </div>
    {delegatedGrantCount > 0 && changes.length === 0 && <div className="identity-gap-callout"><CircleHelp /><div><strong>{tenantWideConsent ? "Tenant-wide delegated consent is present" : "Delegated OAuth consent is present"}</strong><p>The OAuth grant object does not identify the administrator who granted consent. Denali will name a responsible actor only when a matching Entra directory-audit event supplies one.</p></div></div>}
  </DetailSection>;
}

function ObservedActorGroup({
  title,
  empty,
  actors,
  onOpenActivity,
}: {
  title: string;
  empty: string;
  actors: ObservedActor[];
  onOpenActivity: (id: string) => void;
}) {
  return <div className="observed-actor-group"><h4>{title}</h4>{actors.length === 0 ? <p className="observed-actor-empty">{empty}</p> : actors.slice(0, 8).map((actor) => <button key={actor.key} onClick={() => onOpenActivity(actor.latest.id)}><span className="asset-icon violet"><Fingerprint /></span><span><strong>{actor.name}</strong><small>{actor.count} observed {actor.count === 1 ? "event" : "events"} · latest {formatTime(actor.latest.occurred_at)}</small></span><ChevronRight /></button>)}</div>;
}

function RelationshipsTab({ detail, onOpenAsset }: { detail: AssetDetail; onOpenAsset: (id: string) => void }) {
  const topology = detail.relationships.filter((item) => item.category === "topology");
  const capability = detail.relationships.filter((item) => item.category === "capability");
  return <div className="detail-stack"><div className="relationship-summary"><div><Network /><strong>{topology.length}</strong><span>Topology links</span></div><div><Zap /><strong>{capability.length}</strong><span>Capability links</span></div></div>{capability.length > 0 && <DetailSection title="Capabilities"><p className="section-explainer">Capability means an authorized action or access path. It does not claim prompt influence or observed execution.</p>{capability.map((relation) => <RelationshipRow key={relation.id} relation={relation} currentId={detail.id} onOpenAsset={onOpenAsset} />)}</DetailSection>}<DetailSection title="Topology">{topology.map((relation) => <RelationshipRow key={relation.id} relation={relation} currentId={detail.id} onOpenAsset={onOpenAsset} />)}</DetailSection></div>;
}

function RelationshipRow({ relation, currentId, onOpenAsset }: { relation: Relationship; currentId: string; onOpenAsset: (id: string) => void }) {
  const isSource = relation.source_id === currentId;
  const otherId = isSource ? relation.target_id : relation.source_id;
  const otherKind = isSource ? relation.target_kind : relation.source_kind;
  const otherKey = isSource ? relation.target_natural_key : relation.source_natural_key;
  const itemMeta = meta(otherKind); const Icon = itemMeta.icon;
  return <button className="relationship-row" onClick={() => onOpenAsset(otherId)}><span className={`asset-icon ${itemMeta.color}`}><Icon size={17} /></span><span className="relation-direction">{isSource ? "This resource" : shortKey(otherKey)} <b>{titleCase(relation.kind)}</b> {isSource ? shortKey(otherKey) : "this resource"}</span><span className={`relation-category ${relation.category}`}>{titleCase(relation.category)}</span><ChevronRight size={16} /></button>;
}

function EvidenceTab({ detail }: { detail: AssetDetail }) {
  return <div className="detail-stack"><div className="evidence-principle"><ShieldCheck /><div><strong>Evidence, not recollection</strong><p>Every claim retains its source, locator, observation time, assertion class, and confidence.</p></div></div>{detail.assertions.map((assertion, index) => <DetailSection key={`${assertion.connector_id}-${index}`} title={assertion.display_name}><div className="evidence-card"><div className="evidence-badges"><span>{titleCase(assertion.assertion_type)}</span><span>{Math.round(assertion.confidence * 100)}% confidence</span><span>{assertion.lifecycle_state}</span></div><Property label="Source type" value={assertion.evidence.source_type} /><Property label="Evidence locator" value={assertion.evidence.locator} mono /><Property label="Observed at" value={formatTime(assertion.evidence.observed_at)} /><Property label="Coverage plane" value={assertion.coverage_plane} /><details><summary>Raw evidence payload</summary><pre>{JSON.stringify(assertion.evidence.payload, null, 2)}</pre></details></div></DetailSection>)}</div>;
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) { return <section className="detail-section"><h3>{title}</h3>{children}</section>; }
function Property({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) { return <div className={`property ${mono ? "mono" : ""}`}><span>{label}</span><strong>{value}</strong></div>; }

function ErrorState({ message, onRetry, subject = "inventory" }: { message: string; onRetry?: () => void; subject?: string }) { return <div className="state-page"><CircleAlert /><h2>Denali could not load {subject}</h2><p>{message}</p>{onRetry && <button onClick={() => void onRetry()}><RefreshCw />Try again</button>}</div>; }
function LoadingState({ compact = false }: { compact?: boolean }) { return <div className={`loading-state ${compact ? "compact" : ""}`}><Mountain /><span /><p>Mapping the AI system…</p></div>; }

export default App;
