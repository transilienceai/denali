export type InventoryCategory = "ai" | "supporting" | "components";

export const INVENTORY_CATEGORY_KINDS: Record<InventoryCategory, readonly string[]> = {
  ai: [
    "ai_application",
    "ai_agent",
    "ai_model",
    "model_artifact",
    "mcp_server",
    "ai_tool",
    "ai_guardrail",
    "ai_pipeline",
    "ai_datastore",
    "ai_workload",
    "ai_framework",
    "application_endpoint",
  ],
  supporting: ["code_repository", "cloud_resource", "identity"],
  components: ["software_component"],
};

const KIND_CATEGORY = new Map(
  Object.entries(INVENTORY_CATEGORY_KINDS).flatMap(([category, kinds]) =>
    kinds.map((kind) => [kind, category as InventoryCategory] as const),
  ),
);

export function inventoryCategory(value: unknown): InventoryCategory {
  return value === "supporting" || value === "components" ? value : "ai";
}

export function inventoryCategoryForKind(kind: unknown): InventoryCategory | undefined {
  return typeof kind === "string" ? KIND_CATEGORY.get(kind) : undefined;
}

export function inventoryCategoryCount(
  byKind: Readonly<Record<string, number>>,
  category: InventoryCategory,
): number {
  return INVENTORY_CATEGORY_KINDS[category].reduce(
    (total, kind) => total + (byKind[kind] ?? 0),
    0,
  );
}

export function inventoryKinds(
  byKind: Readonly<Record<string, number>>,
  category: InventoryCategory,
): string[] {
  return INVENTORY_CATEGORY_KINDS[category]
    .filter((kind) => (byKind[kind] ?? 0) > 0)
    .sort((left, right) => left.localeCompare(right));
}
