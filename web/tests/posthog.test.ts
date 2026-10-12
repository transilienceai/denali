import assert from "node:assert/strict";
import test from "node:test";
import type { CaptureResult } from "posthog-js";
import { PAGE_PATHS } from "../src/navigation.ts";
import { posthogConfig, sanitizePostHogEvent } from "../src/posthog.ts";

function event(properties: Record<string, unknown>, name = "$pageview"): CaptureResult {
  return { uuid: "test-event", event: name, properties };
}

test("PostHog keeps all known routes while removing callback codes and selected IDs", () => {
  for (const path of Object.values(PAGE_PATHS)) {
    const result = sanitizePostHogEvent(event({
      $current_url: `https://denali.transilience.cloud${path}?code=private&drawer=asset&id=private#evidence`,
      $pathname: `${path}?id=private#details`,
    }));
    assert.deepEqual(result?.properties, {
      $current_url: `https://denali.transilience.cloud${path}`,
      $pathname: path,
    });
  }
});

test("PostHog normalizes unknown resource paths and all attribution URL fields", () => {
  const result = sanitizePostHogEvent(event({
    $current_url: "https://denali.transilience.cloud/private/customer-id?token=private",
    $pathname: "/private/customer-id",
    $initial_current_url: "https://denali.transilience.cloud/connections?github_setup=private",
    $initial_pathname: "/connections?code=private",
    $session_entry_url: "https://denali.transilience.cloud/inventory/?id=private",
    $session_entry_pathname: "/inventory/",
    $prev_pageview_pathname: "/profile?email=private",
  }));
  assert.deepEqual(result?.properties, {
    $current_url: "https://denali.transilience.cloud/other",
    $pathname: "/other",
    $initial_current_url: "https://denali.transilience.cloud/connections",
    $initial_pathname: "/connections",
    $session_entry_url: "https://denali.transilience.cloud/inventory",
    $session_entry_pathname: "/inventory",
    $prev_pageview_pathname: "/profile",
  });
});

test("PostHog drops malformed URLs, identity, customer data and person updates", () => {
  const source = {
    ...event({
      $current_url: "not a valid absolute URL",
      $initial_current_url: "/connections?code=private",
      $session_entry_url: { private: true },
      $title: "Customer workspace",
      $referrer: "https://private.example/callback?code=private",
      $initial_referrer: "private",
      $utm_campaign: "private",
      $set: { email: "private" },
      $set_once: { name: "private" },
      $groups: { organization: "private" },
      tenant_id: "private",
      email: "private",
      password: "private",
      prompt: "private",
    }),
    $set: { name: "private" },
    $set_once: { email: "private" },
  };
  assert.deepEqual(sanitizePostHogEvent(source), {
    uuid: "test-event", event: "$pageview", timestamp: undefined, properties: {},
  });
});

test("PostHog retains transport and anonymous usage metadata for supported events", () => {
  for (const name of ["$pageview", "$pageleave", "$autocapture"]) {
    const properties = {
      token: "public-project-token",
      distinct_id: "anonymous-browser-id",
      $device_id: "anonymous-device-id",
      $session_id: "anonymous-session-id",
      $browser: "Chrome",
      $process_person_profile: false,
      $event_type: "click",
      $elements_chain: 'button:nth-child="1"',
    };
    assert.deepEqual(sanitizePostHogEvent(event(properties, name))?.properties, properties);
  }
  assert.equal(sanitizePostHogEvent(null), null);
  for (const name of ["$identify", "$groupidentify", "$exception", "custom_payload"]) {
    assert.equal(sanitizePostHogEvent(event({ private: true }, name)), null);
  }
});

test("PostHog captures SPA navigation and clicks with optional data capture disabled", () => {
  assert.equal(posthogConfig.capture_pageview, "history_change");
  assert.equal(posthogConfig.capture_pageleave, true);
  assert.deepEqual(posthogConfig.autocapture, {
    dom_event_allowlist: ["click"], capture_copied_text: false,
  });
  assert.equal(posthogConfig.mask_all_text, true);
  assert.equal(posthogConfig.mask_all_element_attributes, true);
  assert.equal(posthogConfig.person_profiles, "never");
  assert.equal(posthogConfig.cross_subdomain_cookie, false);
  assert.equal(posthogConfig.save_campaign_params, false);
  assert.equal(posthogConfig.save_referrer, false);
  assert.equal(posthogConfig.disable_session_recording, true);
  assert.equal(posthogConfig.advanced_disable_flags, true);
  assert.equal(posthogConfig.capture_exceptions, false);
  assert.equal(posthogConfig.capture_performance, false);
  assert.equal(posthogConfig.capture_heatmaps, false);
  assert.equal(posthogConfig.disable_surveys, true);
  assert.equal(posthogConfig.disable_product_tours, true);
  assert.equal(posthogConfig.disable_conversations, true);
  assert.equal(posthogConfig.before_send, sanitizePostHogEvent);
});
