# Anonymous browser product analytics

Denali can send page views, page leaves, and masked clicks to PostHog. The frontend initializes
the SDK before rendering React and captures browser history changes. Existing Vercel Web
Analytics remains available independently.

## Public build configuration

Vite reads the root `.env` file in local development. The example leaves PostHog disabled:

```text
VITE_POSTHOG_PROJECT_TOKEN=
VITE_POSTHOG_HOST=https://us.i.posthog.com
```

For a hosted build, configure these variables on the intended Vercel project and environment.
Use the PostHog project's public ingestion token from its installation instructions. Never use
a PostHog personal API key, Clerk secret, database DSN, or provider credential. Vite publishes
every `VITE_*` value in the browser bundle. Keep actual token values out of commits, logs,
screenshots, and PR descriptions.

An absent or blank project token skips initialization. Production and Preview settings are
independent; leave capture disabled where usage should not reach the selected PostHog project.
Environment variable changes require a new frontend build. Production builds follow the normal
[branch, PR, merge, and release process](change-and-release-process.md).

## Event boundary

The SDK uses random browser and session identifiers for anonymous usage. It never identifies a
Clerk user or Organization, creates a person profile, or attaches Denali tenant/customer IDs.
Only `$pageview`, `$pageleave`, and click `$autocapture` events pass the sanitizer. Their property
allowlist retains the transport project token, anonymous SDK identifiers, timestamps,
browser/device/viewport metadata, sanitized page locations, and structural click metadata.

Page locations retain only their origin and a known static application path. Query strings and
hashes are removed, so drawer IDs, filters, provider callback codes, and other selections are
excluded. Unknown or dynamic paths become `/other`. DOM text and element attributes are masked;
click structure can retain tag names and element positions. Page titles, referrers, attribution,
form values, copied text, arbitrary custom properties, and person-property updates are excluded.

Session replay, feature flags, surveys, product tours, conversations, heatmaps, dead/rage clicks,
and automatic exception/performance capture are disabled in code. Project-side settings do not
authorize adding customer content, prompts, responses, credentials, raw evidence, or identity
properties to this telemetry. Future analytics changes must preserve this boundary and include
focused sanitizer tests.

## Verify and disable

1. Run the frontend tests and production build. The sanitizer tests must show that query/hash
   data, unknown paths, identity properties, DOM content, and unsupported events are removed.
2. After deployment, load a known route and navigate to another page without changing customer
   data. In the selected PostHog project's live events, confirm page views arrive with the
   expected static paths and anonymous identifiers.
3. Open the event properties and verify there are no query strings, hashes, customer IDs,
   email addresses, Clerk identifiers, DOM text, or person-property updates. A masked navigation
   click may contain only structural element metadata.
4. Confirm the hosted same-origin API and authorization smoke checks still pass as required by
   the release process. Analytics success does not establish API or provider acceptance.

To disable PostHog, remove or clear `VITE_POSTHOG_PROJECT_TOKEN` in the affected environment and
rebuild the frontend. Follow the normal reviewed release path for a code rollback. Backend
secrets, migrations, provider permissions, CLI scopes, and gateway contracts are unaffected.
