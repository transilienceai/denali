import type { CaptureResult, PostHogConfig } from "posthog-js";
import { PAGE_PATHS } from "./navigation.ts";

const paths = new Set<string>(Object.values(PAGE_PATHS));

function pagePath(value: string): string {
  const pathname = new URL(value, "https://analytics.invalid").pathname;
  const normalized = pathname.replace(/\/+$/, "") || "/";
  return paths.has(normalized) ? normalized : "/other";
}

// Provider callbacks, selected resources and account details can appear in URLs
// and DOM content. Only anonymous usage metadata may leave the browser.
const properties = new Set([
  "token", "distinct_id", "$device_id", "$session_id", "$window_id",
  "$lib", "$lib_version", "$insert_id", "$time", "$process_person_profile",
  "$browser", "$browser_version", "$browser_type", "$os", "$os_version",
  "$device_type", "$screen_height", "$screen_width", "$viewport_height", "$viewport_width",
  "$current_url", "$pathname", "$session_entry_url", "$session_entry_pathname",
  "$initial_current_url", "$initial_pathname", "$prev_pageview_pathname",
  "$event_type", "$elements_chain", "$geoip_disable",
]);

export function sanitizePostHogEvent(event: CaptureResult | null): CaptureResult | null {
  if (!event || !["$pageview", "$pageleave", "$autocapture"].includes(event.event)) return null;
  const clean: CaptureResult["properties"] = {};
  for (const [key, value] of Object.entries(event.properties)) {
    if (!properties.has(key)) continue;
    if (key.endsWith("url") || key.endsWith("pathname")) {
      if (typeof value !== "string") continue;
      try {
        clean[key] = key.endsWith("url")
          ? `${new URL(value).origin}${pagePath(value)}`
          : pagePath(value);
      } catch {
        // Malformed attribution URLs are omitted instead of sent unfiltered.
      }
    } else {
      clean[key] = value;
    }
  }
  return { uuid: event.uuid, event: event.event, timestamp: event.timestamp, properties: clean };
}

export const posthogConfig: Partial<PostHogConfig> = {
  defaults: "2026-05-30",
  capture_pageview: "history_change",
  capture_pageleave: true,
  autocapture: { dom_event_allowlist: ["click"], capture_copied_text: false },
  mask_all_text: true,
  mask_all_element_attributes: true,
  person_profiles: "never",
  cross_subdomain_cookie: false,
  save_campaign_params: false,
  save_referrer: false,
  disable_capture_url_hashes: true,
  disable_session_recording: true,
  capture_exceptions: false,
  capture_performance: false,
  capture_heatmaps: false,
  capture_dead_clicks: false,
  rageclick: false,
  disable_surveys: true,
  disable_product_tours: true,
  disable_conversations: true,
  advanced_disable_flags: true,
  before_send: sanitizePostHogEvent,
};
