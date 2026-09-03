export type Page =
  | "dashboard"
  | "connections"
  | "inventory"
  | "shadowAi"
  | "findings"
  | "vulnerabilities"
  | "issues"
  | "codeToCloud"
  | "runtime"
  | "detections"
  | "sources"
  | "profile";

export type DrawerKind =
  | "asset"
  | "finding"
  | "vulnerability"
  | "issue"
  | "activity"
  | "detection";

export interface NavigationLocation {
  page: Page;
  query: Readonly<Record<string, string>>;
  drawer: { kind: DrawerKind; id: string; tab: string } | null;
}

export interface OverlayHistoryState {
  overlayDepth: number;
  overlayParent?: string;
}

export interface NavigationTransition {
  page: Page;
  query: Readonly<Record<string, string>>;
  mode: "push" | "replace";
  state: OverlayHistoryState;
}

export const AI_APPLICATION_DISCOVERY_LABEL = "AI application discovery";

export type DrawerCloseTransition =
  | { delta: number }
  | NavigationTransition;

export const PAGE_PATHS: Record<Page, string> = {
  dashboard: "/",
  connections: "/connections",
  inventory: "/inventory",
  shadowAi: "/shadow-ai",
  findings: "/posture-findings",
  vulnerabilities: "/vulnerabilities",
  issues: "/issues",
  codeToCloud: "/code-to-cloud",
  runtime: "/runtime-activity",
  detections: "/detections",
  sources: "/sources",
  profile: "/profile",
};

const PATH_PAGES = new Map(
  Object.entries(PAGE_PATHS).map(([page, path]) => [path, page as Page]),
);

const DRAWER_TABS: Record<DrawerKind, readonly string[]> = {
  asset: ["overview", "relationships", "evidence"],
  finding: ["overview", "evidence", "history"],
  vulnerability: ["overview", "evidence", "sources"],
  issue: ["overview", "path", "evidence"],
  activity: ["overview", "evidence"],
  detection: ["overview", "evidence"],
};

const DRAWER_KINDS = new Set<DrawerKind>(Object.keys(DRAWER_TABS) as DrawerKind[]);
const MAX_QUERY_VALUE = 500;

export function pageFromPath(pathname: string): Page {
  const normalized = pathname.replace(/\/+$/, "") || "/";
  return PATH_PAGES.get(normalized) ?? "dashboard";
}

export function hasConnectionReturn(query: URLSearchParams): boolean {
  return (
    query.has("github_setup") ||
    (query.has("state") && (query.has("admin_consent") || query.has("error")))
  );
}

export function navigationFromUrl(input: string | URL): NavigationLocation {
  const url = typeof input === "string" ? new URL(input, "http://denali.local") : input;
  const search = new URLSearchParams(url.search);
  const page = hasConnectionReturn(search) ? "connections" : pageFromPath(url.pathname);
  const query: Record<string, string> = {};
  for (const [key, value] of search) {
    if (value && value.length <= MAX_QUERY_VALUE) query[key] = value;
  }
  const rawKind = query.drawer;
  const id = query.id;
  let drawer: NavigationLocation["drawer"] = null;
  if (DRAWER_KINDS.has(rawKind as DrawerKind) && id) {
    const kind = rawKind as DrawerKind;
    const requestedTab = query.tab;
    const tab = DRAWER_TABS[kind].includes(requestedTab) ? requestedTab : "overview";
    drawer = { kind, id, tab };
    if (tab === "overview") delete query.tab;
    else query.tab = tab;
  } else {
    delete query.drawer;
    delete query.id;
    delete query.tab;
  }
  return { page, query, drawer };
}

export function navigationUrl(
  page: Page,
  query: Readonly<Record<string, string | null | undefined>> = {},
): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value) search.set(key, value);
  }
  const suffix = search.toString();
  return `${PAGE_PATHS[page]}${suffix ? `?${suffix}` : ""}`;
}

export function inventoryQuery(kind: unknown): Record<string, string> {
  return typeof kind === "string" && kind !== "all" ? { kind } : {};
}

export function queryWith(
  current: Readonly<Record<string, string>>,
  updates: Readonly<Record<string, string | null | undefined>>,
): Record<string, string> {
  const next = { ...current };
  for (const [key, value] of Object.entries(updates)) {
    if (value) next[key] = value;
    else delete next[key];
  }
  return next;
}

export function withoutDrawer(
  query: Readonly<Record<string, string>>,
): Record<string, string> {
  return queryWith(query, { drawer: null, id: null, tab: null });
}

export function drawerTabs(kind: DrawerKind): readonly string[] {
  return DRAWER_TABS[kind];
}

export function openDrawerTransition(
  current: NavigationLocation,
  historyState: Partial<OverlayHistoryState> | null | undefined,
  kind: DrawerKind,
  id: string,
): NavigationTransition {
  const depth = Number(historyState?.overlayDepth) || 0;
  const mode = current.drawer && depth === 0 ? "replace" : "push";
  return {
    page: current.page,
    query: queryWith(current.query, { drawer: kind, id, tab: null }),
    mode,
    state: {
      overlayDepth: mode === "push" ? depth + 1 : 0,
      overlayParent:
        historyState?.overlayParent ??
        navigationUrl(current.page, withoutDrawer(current.query)),
    },
  };
}

export function drawerTabTransition(
  current: NavigationLocation,
  historyState: Partial<OverlayHistoryState> | null | undefined,
  tab: string,
): NavigationTransition | null {
  if (!current.drawer || current.drawer.tab === tab) return null;
  const depth = Number(historyState?.overlayDepth) || 0;
  const mode = depth === 0 ? "replace" : "push";
  return {
    page: current.page,
    query: queryWith(current.query, { tab: tab === "overview" ? null : tab }),
    mode,
    state: {
      overlayDepth: mode === "push" ? depth + 1 : 0,
      overlayParent:
        historyState?.overlayParent ??
        navigationUrl(current.page, withoutDrawer(current.query)),
    },
  };
}

export function closeDrawerTransition(
  current: NavigationLocation,
  historyState: Partial<OverlayHistoryState> | null | undefined,
): DrawerCloseTransition {
  const depth = Number(historyState?.overlayDepth) || 0;
  if (depth > 0) return { delta: -depth };
  return {
    page: current.page,
    query: withoutDrawer(current.query),
    mode: "replace",
    state: { overlayDepth: 0 },
  };
}
